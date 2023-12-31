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
server.get("/employees/:id", (req, res) => {
  const employeeId = Number(req.params.id);

  const employee = router.db.get("employees").find({ id: employeeId }).value();

  if (!employee) {
    return res.status(404).json({ error: "Nhân viên không tồn tại" });
  }

  // Tìm thông tin chi tiết của manager
  const manager =
    router.db.get("employees").find({ id: employee.manager }).value() ?? null;

  // Tìm các dự án mà nhân viên đang tham gia
  const projects = router.db
    .get("projects")
    .filter((project) => project.employees.some((e) => e.id === employeeId))
    .map((project) => {
      const { employees, ...projectWithoutEmployees } = project;
      const employeeInProject = employees.find((e) => e.id === employeeId);
      const periods = employeeInProject ? employeeInProject.periods : [];
      return { ...projectWithoutEmployees, periods, role: [employee.position] };
    })
    .value();

  // Tìm các dự án mà nhân viên đang quản lý
  const managedProjects = router.db
    .get("projects")
    .filter((project) => project.manager === employeeId)
    .map((project) => {
      return { ...project, role: ["Project Manager"] };
    })
    .value();

  // Kết hợp hai mảng dự án lại
  const allProjects = [...projects, ...managedProjects];

  // Loại bỏ các dự án trùng lặp và thêm vai trò tương ứng
  const uniqueProjects = allProjects.reduce((acc, project) => {
    const existingProject = acc.find((p) => p.id === project.id);
    if (existingProject) {
      existingProject.role = [
        ...new Set([...existingProject.role, ...project.role]),
      ];
    } else {
      acc.push(project);
    }
    return acc;
  }, []);

  const employeeWithProjects = {
    ...employee,
    projects: uniqueProjects,
    manager,
  };

  res.status(200).json(employeeWithProjects);
});

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

      // Kiểm tra xem mã, email hoặc số điện thoại đã tồn tại chưa
      const existingCode = router.db
        .get("employees")
        .find({ code: req.body.code })
        .value();
      if (existingCode) {
        return res
          .status(400)
          .json({ error: "Mã đã tồn tại", status: "code_exists" });
      }

      const existingEmail = router.db
        .get("employees")
        .find({ email: req.body.email })
        .value();
      if (existingEmail) {
        return res
          .status(400)
          .json({ error: "Email đã tồn tại", status: "email_exists" });
      }

      const existingPhone = router.db
        .get("employees")
        .find({ phone: req.body.phone })
        .value();
      if (existingPhone) {
        return res
          .status(400)
          .json({ error: "Số điện thoại đã tồn tại", status: "phone_exists" });
      }

      const existingIdentity = router.db
        .get("employees")
        .find({ identity: req.body.identity })
        .value();
      if (existingIdentity) {
        return res.status(400).json({
          error: "CCCD đã tồn tại",
          status: "identity_exists",
        });
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
        manager: req.body.manager ? Number(req.body.manager) : null,
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
      .filter(
        (employee) =>
          (employee.is_manager === true || employee.is_manager === "true") &&
          employee.status === "active"
      )
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

      // Kiểm tra xem nhân viên có đang tham gia vào một dự án nào không
      const project =
        router.db.get("projects").find({ manager: employeeId }).value() ||
        router.db
          .get("projects")
          .find((project) =>
            project.employees.some((emp) => emp.id === employeeId)
          )
          .value();

      if (project && updatedEmploy.status === "inactive") {
        return res.status(400).json({
          error:
            "Nhân viên đang tham gia vào một dự án, không thể cập nhật trạng thái thành không hoạt động",
          status: "employee_in_project",
          project_name: project.name,
        });
      }

      // Kiểm tra xem nhân viên có phải là quản lý của nhân viên khác không
      const isManager = router.db
        .get("employees")
        .find({ manager: employeeId })
        .value();

      if (isManager && updatedEmploy.is_manager === "false") {
        return res.status(400).json({
          error:
            "Nhân viên đang là quản lý của nhân viên khác, không thể cập nhật trạng thái is_manager thành false",
          status: "employee_in_manager",
          employee_name: isManager.name,
        });
      }

      // Kiểm tra xem mã, email hoặc số điện thoại đã tồn tại chưa
      const existingCode = router.db
        .get("employees")
        .find({ code: updatedEmploy.code })
        .value();

      if (existingCode && existingCode.id !== employeeId) {
        return res
          .status(400)
          .json({ error: "Mã đã tồn tại", status: "code_exists" });
      }

      const existingEmail = router.db
        .get("employees")
        .find({ email: updatedEmploy.email })
        .value();
      if (existingEmail && existingEmail.id !== employeeId) {
        return res
          .status(400)
          .json({ error: "Email đã tồn tại", status: "email_exists" });
      }

      const existingPhone = router.db
        .get("employees")
        .find({ phone: updatedEmploy.phone })
        .value();
      if (existingPhone && existingPhone.id !== employeeId) {
        return res
          .status(400)
          .json({ error: "Số điện thoại đã tồn tại", status: "phone_exists" });
      }

      const existingIdentity = router.db
        .get("employees")
        .find({ identity: updatedEmploy.identity })
        .value();
      if (existingIdentity && existingIdentity.id !== employeeId) {
        return res
          .status(400)
          .json({ error: "CCCD đã tồn tại", status: "identity_exists" });
      }

      if (req.file) {
        const result = await cloudinary.uploader.upload(req.file.path);
        updatedEmploy.avatar = result.secure_url; // Cập nhật URL avatar
      }

      updatedEmploy.manager = updatedEmploy.manager
        ? Number(updatedEmploy.manager)
        : null;
      updatedEmploy.updatedAt = new Date().toISOString();

      const updatedEmployInDb = router.db
        .get("employees")
        .find({ id: employeeId })
        .assign(updatedEmploy)
        .write();

      res.status(200).json(updatedEmployInDb);
    } catch (err) {
      res.status(500).send(err);
    }
  }
);

// Xoá một nhân viên
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

    // Tìm và cập nhật các dự án mà nhân viên này đang tham gia
    const projects = router.db.get("projects").value();
    for (let i = 0; i < projects.length; i++) {
      const project = projects[i];

      // Nếu nhân viên này là quản lý của dự án, không cho phép xóa
      if (project.manager === employeeId) {
        return res.status(400).json({
          error: `Không thể xóa nhân viên vì đang là quản lý của dự án ${project.name}`,
          project_name: project.name,
          status: "required_manager",
        });
      }

      // Nếu nhân viên này là duy nhất trong danh sách nhân viên của dự án, không cho phép xóa
      if (
        project.employees.length === 1 &&
        project.employees[0].id === employeeId
      ) {
        return res.status(400).json({
          error: `Không thể xóa nhân viên vì đang là nhân viên duy nhất của dự án ${project.name}`,
          project_name: project.name,
          status: "required_employee",
        });
      }

      // Xóa nhân viên khỏi danh sách nhân viên của dự án
      project.employees = project.employees.filter((e) => e.id !== employeeId);

      // Cập nhật dự án trong cơ sở dữ liệu
      router.db
        .get("projects")
        .find({ id: project.id })
        .assign(project)
        .write();
    }

    // Xóa nhân viên khỏi cơ sở dữ liệu
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

server.put("/projects/:id", (req, res) => {
  const projectId = Number(req.params.id);
  const updatedProject = req.body;

  const project = router.db.get("projects").find({ id: projectId }).value();

  if (!project) {
    return res.status(404).json({ error: "Dự án không tồn tại" });
  }

  // Cập nhật leaving_time cho nhân viên không còn trong dự án
  project.employees.forEach((employee) => {
    const updatedEmployee = updatedProject.employees.find(
      (e) => e.id === employee.id
    );
    if (!updatedEmployee) {
      const leavingPeriod = employee.periods.find(
        (period) => period.leaving_time === null
      );
      if (leavingPeriod) {
        leavingPeriod.leaving_time = new Date().toISOString();
      }
    }
  });

  // Thêm một đối tượng mới với joining_time và leaving_time là null cho nhân viên được thêm vào dự án
  updatedProject.employees.forEach((updatedEmployee) => {
    const employee = project.employees.find((e) => e.id === updatedEmployee.id);
    if (!employee) {
      const newEmployee = { ...updatedEmployee, periods: [] };
      newEmployee.periods.push({
        joining_time: new Date().toISOString(),
        leaving_time: null,
      });
      project.employees.push(newEmployee);
    } else {
      // Nếu nhân viên đã từng là một phần của dự án, thêm một khoảng thời gian làm việc mới
      const lastPeriod = employee.periods[employee.periods.length - 1];
      if (lastPeriod && lastPeriod.leaving_time !== null) {
        employee.periods.push({
          joining_time: new Date().toISOString(),
          leaving_time: null,
        });
      }
    }
  });

  // Cập nhật các trường khác của dự án
  project.name = updatedProject.name;
  project.manager = updatedProject.manager;
  project.status = updatedProject.status;
  project.start_date = updatedProject.start_date;
  project.end_date = updatedProject.end_date;
  project.description = updatedProject.description;
  project.technical = updatedProject.technical;

  router.db.get("projects").find({ id: projectId }).assign(project).write();

  res.status(200).json(project);
});

server.get(
  "/employees/:id/projects",
  authenticateToken,
  requireAdminRole,
  (req, res) => {
    const db = router.db; // lowdb instance
    const employeeId = Number(req.params.id);

    // Tìm nhân viên với id được truyền vào
    const employee = db.get("employees").find({ id: employeeId }).value();

    // Lấy ra tất cả các dự án
    let projects = db.get("projects").value();

    // Lọc ra những dự án mà nhân viên đang tham gia
    projects = projects.filter((project) =>
      project.employees.some((e) => e.id === employeeId)
    );

    // Lấy thông tin chi tiết của từng nhân viên trong dự án
    projects = projects.map((project) => {
      const projectCopy = { ...project };
      projectCopy.employees = project.employees
        .map((e) => {
          // Kiểm tra xem employee.id có tồn tại không
          if (e.id) {
            const employeeDetail = db
              .get("employees")
              .find({ id: e.id })
              .value();
            // Tạo một bản sao của employeeDetail
            const employeeDetailCopy = { ...employeeDetail };
            // Reset role array
            employeeDetailCopy.role = [];
            // Kiểm tra xem nhân viên có phải là manager của dự án hay không
            if (project.manager === e.id) {
              // Đặt vai trò là "Project Manager"
              employeeDetailCopy.role.push("Project Manager");
            }
            // Đặt vai trò là vị trí hiện tại của nhân viên
            employeeDetailCopy.role.push(employeeDetail.position);
            return employeeDetailCopy;
          } else {
            console.log("Employee without id found in project:", project);
            return null;
          }
        })
        .filter((e) => e !== null); // Loại bỏ nhân viên không có id

      // Thêm dữ liệu của nhân viên đang được truyền id vào
      // Thêm dữ liệu của nhân viên đang được truyền id vào
      projectCopy.currentEmployee = { ...employee };
      // Reset role array
      projectCopy.currentEmployee.role = [];
      // Kiểm tra xem nhân viên có phải là manager của dự án hay không
      if (project.manager === employeeId) {
        // Đặt vai trò là "Project Manager"
        projectCopy.currentEmployee.role.push("Project Manager");
      }
      // Đặt vai trò là vị trí hiện tại của nhân viên
      projectCopy.currentEmployee.role.push(employee.position);

      return projectCopy;
    });

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
  const detailedEmployees = project.employees
    .map((employee) => {
      const employeeDetails = db
        .get("employees")
        .find({ id: employee.id })
        .value();
      return {
        ...employeeDetails,
        periods: employee.periods,
      };
    })
    .filter((employee) => employee !== null); // Loại bỏ nhân viên không có id

  // Trả về dự án với thông tin chi tiết của nhân viên và giữ lại periods
  res.json({ ...project, employees: detailedEmployees });
});

server.use(router);
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
