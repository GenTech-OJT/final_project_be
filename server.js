const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const _ = require("lodash");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

const SECRET_KEY = "gentech-secret-key";
const REFRESH_SECRET_KEY = "gentech-refresh-secret-key";

const port = process.env.PORT || 3000;

server.use(middlewares);
server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(cors());

//Middleware xác thực token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res
      .status(401)
      .json({ error: "Token xác thực không được cung cấp" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token xác thực đã hết hạn" });
      }
      return res.status(403).json({ error: "Token xác thực không hợp lệ" });
    }

    // Giả sử `user` chỉ chứa ID người dùng
    const dbUser = router.db.get("users").find({ id: user.id }).value();

    if (!dbUser) {
      return res.status(403).json({ error: "Người dùng không tồn tại" });
    }

    // Đặt `req.user` để middleware sau có thể sử dụng
    req.user = dbUser;

    next();
  });
};

const requireAdminRole = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Chỉ admin mới có quyền thực hiện" });
  }
  next();
};

// Đăng nhập người dùng
server.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Tìm người dùng trong cơ sở dữ liệu
  const user = router.db.get("users").find({ email }).value();
  if (!user) {
    return res.status(404).json({ error: "Người dùng không tồn tại" });
  }

  if (!user.verified) {
    return res.status(401).json({ error: "Người dùng chưa xác thực" });
  }

  // So sánh password đã hash
  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) {
      return res
        .status(500)
        .json({ error: "Lỗi trong quá trình xác thực mật khẩu" });
    }
    if (!isMatch) {
      return res.status(401).json({ error: "Mật khẩu không chính xác" });
    }

    // Tạo token JWT
    const accessToken = jwt.sign({ id: user.id }, SECRET_KEY, {
      expiresIn: "10h",
    });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET_KEY);

    router.db
      .get("users")
      .find({ email })
      .assign({ accessToken, refreshToken })
      .write();

    // Trả về thông tin người dùng và token
    const {
      password,
      accessToken: userAccessToken,
      refreshToken: userRefreshToken,
      ...userWithoutSensitiveInfo
    } = user;

    res
      .status(200)
      .json({ user: userWithoutSensitiveInfo, accessToken, refreshToken });
  });
});

server.post("/refresh-token", (req, res) => {
  // Lấy refresh token từ body yêu cầu
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(403).json({ error: "Refresh token is required" });
  }

  // Tìm refresh token trong cơ sở dữ liệu
  const user = router.db.get("users").find({ refreshToken }).value();

  if (!user) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }

  // Kiểm tra refresh token
  jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, userData) => {
    if (err) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    // Tạo access token mới
    const accessToken = jwt.sign({ id: user.id }, SECRET_KEY, {
      expiresIn: "10h",
    });

    // Cập nhật access token trong cơ sở dữ liệu
    router.db
      .get("users")
      .find({ refreshToken })
      .assign({ accessToken })
      .write();

    // Trả về access token mới
    res.status(200).json({ accessToken });
  });
});

server.get("/dashboard", authenticateToken, requireAdminRole, (req, res) => {
  try {
    const employeeCount = router.db.get("employees").size().value();
    const projectCount = router.db.get("projects").size().value();
    const positionCount = router.db.get("positions").size().value();

    const skillCounts = {};
    const employees = router.db.get("employees").value();

    employees.forEach((employee) => {
      employee.skills.forEach((skill) => {
        if (!skillCounts[skill.name]) {
          skillCounts[skill.name] = 0;
        }
        skillCounts[skill.name]++;
      });
    });

    const skillsArray = Object.keys(skillCounts).map((skill) => ({
      name: skill,
      count: skillCounts[skill],
    }));

    res.status(200).json({
      employeeCount,
      projectCount,
      positionCount,
      skillsArray,
    });
  } catch (err) {
    console.log(err);
    res.status(500).send(err);
  }
});

server.get("/employees", authenticateToken, requireAdminRole, (req, res) => {
  let db = router.db; // lowdb instance

  let employees = db.get("employees").value(); // convert to array

  // Filter
  if (req.query.name) {
    employees = employees.filter((user) => user.name.includes(req.query.name));
  }

  // Search
  if (req.query.q) {
    const searchTerm = req.query.q.toLowerCase();

    employees = employees.filter((user) =>
      user.name.toLowerCase().includes(searchTerm)
    );
  }

  // Sort
  if (req.query._sort && req.query._order) {
    employees = _.orderBy(employees, req.query._sort, req.query._order);
  }

  // Paginate
  const _page = req.query._page || 1;
  const _limit = req.query._limit || 10;
  const start = (_page - 1) * _limit;
  const end = _page * _limit;

  const paginatedEmployees = employees.slice(start, end);

  res.json({
    pagination: {
      total: employees.length,
      page: _page,
      limit: _limit,
    },
    sort: {
      field: req.query._sort || "id",
      order: req.query._order || "asc",
    },
    data: paginatedEmployees,
  });
});

// Lấy thông tin chi tiết nhaan vieen
server.get(
  "/employees/:id",
  // authenticateToken,
  // requireAdminRole,
  (req, res) => {
    const employeeId = Number(req.params.id);

    const employee = router.db
      .get("employees")
      .find({ id: employeeId })
      .value();

    if (!employee) {
      return res.status(404).json({ error: "Nhân viên không tồn tại" });
    }

    res.status(200).json(employee);
  }
);

cloudinary.config({
  cloud_name: "dadt9qw4k",
  api_key: "218768144543215",
  api_secret: "iMFvVcGooOnqSfFyA-eTAnMq_zU",
});
const upload = multer({ dest: "/tmp/" });

// Tạo mới một nhân viên
server.post(
  "/employees",
  authenticateToken,
  requireAdminRole,
  upload.single("avatar"),
  async (req, res) => {
    try {
      let avatarUrl = ""; // URL mặc định hoặc trống
      if (req.file) {
        const result = await cloudinary.uploader.upload(req.file.path);
        avatarUrl = result.secure_url;
      }

      // Tìm ID lớn nhất hiện tại
      const maxId = Math.max(
        ...router.db
          .get("employees")
          .value()
          .map((employee) => employee.id),
        0
      );

      const newEmploy = {
        id: maxId + 1,
        ...req.body,
        avatar: avatarUrl,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      router.db.get("employees").push(newEmploy).write();
      res.status(201).json(newEmploy);
    } catch (err) {
      res.status(500).send(err);
    }
  }
);

server.get("/managers", (req, res) => {
  try {
    const managers = router.db
      .get("employees")
      .filter({ is_manager: true || is_manager === "true" })
      .value();
    res.status(200).json(managers);
  } catch (err) {
    res.status(500).send(err);
  }
});

// API để lấy danh sách các vị trí
server.get("/positions", (req, res) => {
  try {
    const positions = router.db.get("positions").value();
    res.status(200).json(positions);
  } catch (err) {
    res.status(500).send(err);
  }
});

// Cập nhật thông tin của nhaan vieen
server.put(
  "/employees/:id",
  authenticateToken,
  requireAdminRole,
  upload.single("avatar"),
  async (req, res) => {
    try {
      const employeeId = Number(req.params.id);
      const updatedEmploy = req.body;

      const employee = router.db
        .get("employees")
        .find({ id: employeeId })
        .value();

      if (!employee) {
        return res.status(404).json({ error: "Nhân viên không tồn tại" });
      }

      if (req.file) {
        const result = await cloudinary.uploader.upload(req.file.path);
        updatedEmploy.avatar = result.secure_url; // Cập nhật URL avatar
      }

      updatedEmploy.updatedAt = new Date().toISOString();

      const updatedEmployInDb = router.db
        .get("employees")
        .find({ id: employeeId })
        .assign(updatedEmploy)
        .write();

      res.status(200).json(updatedEmployInDb);
    } catch (err) {
      console.log(err);
      res.status(500).send(err);
    }
  }
);

// Xóa một nhaan vien
server.delete(
  "/employees/:id",
  authenticateToken,
  requireAdminRole,
  (req, res) => {
    const employeeId = Number(req.params.id);

    const employee = router.db
      .get("employees")
      .find({ id: employeeId })
      .value();

    if (!employee) {
      return res.status(404).json({ error: "Nhân viên không tồn tại" });
    }

    router.db.get("employees").remove({ id: employeeId }).write();

    res.status(200).json({ message: "Nhân viên đã được xóa" });
  }
);

server.get("/projects", authenticateToken, requireAdminRole, (req, res) => {
  let db = router.db; // lowdb instance

  let projects = db.get("projects").value(); // convert to array

  // Get detailed information for manager and employees
  projects = projects.map((project) => {
    const manager = db.get("employees").find({ id: project.manager }).value();
    const employees = project.employees.map((employee) => {
      const employeeDetails = db
        .get("employees")
        .find({ id: employee.id })
        .value();
      return {
        ...employeeDetails,
        periods: employee.periods,
      };
    });

    return {
      ...project,
      manager,
      employees,
    };
  });

  // Filter
  if (req.query.name) {
    projects = projects.filter((project) =>
      project.name.includes(req.query.name)
    );
  }

  // Search
  if (req.query.q) {
    const searchTerm = req.query.q.toLowerCase();

    projects = projects.filter((project) =>
      project.name.toLowerCase().includes(searchTerm)
    );
  }

  // Sort
  if (req.query._sort && req.query._order) {
    projects = _.orderBy(projects, req.query._sort, req.query._order);
  }

  // Paginate
  const _page = req.query._page || 1;
  const _limit = req.query._limit || 10;
  const start = (_page - 1) * _limit;
  const end = _page * _limit;

  const paginatedProjects = projects.slice(start, end);

  res.json({
    pagination: {
      total: projects.length,
      page: _page,
      limit: _limit,
    },
    sort: {
      field: req.query._sort || "id",
      order: req.query._order || "asc",
    },
    data: paginatedProjects,
  });
});

server.post("/projects", authenticateToken, requireAdminRole, (req, res) => {
  // Tìm ID lớn nhất hiện tại
  const maxId = Math.max(
    ...router.db
      .get("projects")
      .value()
      .map((project) => project.id),
    0
  );

  const project = {
    id: maxId + 1,
    ...req.body,
    manager: Number(req.body.manager),
    employees: req.body.employees.map((employee) => ({
      id: Number(employee.id),
      periods: [
        {
          joining_time: new Date().toISOString(),
          leaving_time: null,
        },
      ],
    })),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  router.db.get("projects").push(project).write();

  res.status(201).json(project);
});

server.put("/projects/:id", authenticateToken, requireAdminRole, (req, res) => {
  const project = router.db
    .get("projects")
    .find({ id: Number(req.params.id) })
    .value();

  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }

  // Kiểm tra xem tất cả nhân viên có tồn tại không
  const employees = router.db.get("employees").value();
  const employeeIds = employees.map((employee) => employee.id);
  for (let employee of req.body.employees) {
    if (!employeeIds.includes(Number(employee.id))) {
      return res
        .status(400)
        .json({ error: `Employee with id ${employee.id} does not exist` });
    }
  }

  const updatedProject = {
    ...project,
    ...req.body,
    manager: Number(req.body.manager), // convert to number
    employees: req.body.employees.map((employee) => ({
      id: Number(employee.id), // convert to number
      periods: employee.periods.map((period) => ({
        joining_time: period.joining_time,
        leaving_time: period.leaving_time ? period.leaving_time : null,
      })),
    })),
    updatedAt: new Date().toISOString(),
  };

  router.db
    .get("projects")
    .find({ id: Number(req.params.id) })
    .assign(updatedProject)
    .write();

  res.json(updatedProject);
});

server.get(
  "/employees/:id/projects",
  authenticateToken,
  requireAdminRole,
  (req, res) => {
    const db = router.db; // lowdb instance
    const employeeId = Number(req.params.id);

    // Lấy ra tất cả các dự án
    let projects = db.get("projects").value();

    // Lọc ra những dự án mà nhân viên đang tham gia
    projects = projects.filter((project) =>
      project.employees.some((e) => e.id === employeeId)
    );

    // Lấy thông tin chi tiết của từng nhân viên trong dự án
    projects = projects.map((project) => {
      project.employees = project.employees
        .map((employee) => {
          console.log("employee", employee);
          // Kiểm tra xem employee.id có tồn tại không
          if (employee.id) {
            return db.get("employees").find({ id: employee.id }).value();
          } else {
            console.log("Employee without id found in project:", project);
            return null;
          }
        })
        .filter((employee) => employee !== null); // Loại bỏ nhân viên không có id
      return project;
    });

    // Search
    if (req.query.q) {
      const searchTerm = req.query.q.toLowerCase();
      projects = projects.filter((project) =>
        project.name.toLowerCase().includes(searchTerm)
      );
    }

    res.json(projects);
  }
);

server.delete(
  "/projects/:id",
  authenticateToken,
  requireAdminRole,
  (req, res) => {
    const db = router.db; // lowdb instance
    const projectId = Number(req.params.id);

    // Tìm dự án cần xóa
    const project = db.get("projects").find({ id: projectId }).value();

    // Nếu không tìm thấy dự án, trả về lỗi
    if (!project) {
      return res.status(404).json({ error: "Dự án không tồn tại" });
    }

    // Xóa dự án
    db.get("projects").remove({ id: projectId }).write();

    res.json({ message: "Dự án đã được xóa thành công" });
  }
);

server.get("/projects/:id", authenticateToken, requireAdminRole, (req, res) => {
  const db = router.db; // lowdb instance
  const projectId = Number(req.params.id);

  // Tìm dự án với id được truyền vào
  let project = db.get("projects").find({ id: projectId }).value();

  // Nếu không tìm thấy dự án, trả về lỗi
  if (!project) {
    return res.status(404).json({ error: "Dự án không tồn tại" });
  }

  // Lấy thông tin chi tiết của từng nhân viên trong dự án
  project.employees = project.employees
    .map((employee) => {
      // Kiểm tra xem employee.id có tồn tại không
      if (employee.id) {
        return db.get("employees").find({ id: employee.id }).value();
      } else {
        console.log("Employee without id found in project:", project);
        return null;
      }
    })
    .filter((employee) => employee !== null); // Loại bỏ nhân viên không có id

  res.json(project);
});

server.use(router);
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
