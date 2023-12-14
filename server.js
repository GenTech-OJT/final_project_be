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

// Middleware để thêm createdAt và updatedAt
server.use((req, res, next) => {
  if (req.method === "POST" || req.method === "PUT") {
    const timestamp = new Date().toISOString();
    req.body.createdAt = req.body.createdAt || timestamp;
    req.body.updatedAt = timestamp;
  }
  next();
});

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
    const accessToken = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET_KEY);

    router.db.get("users").find({ email }).assign({ accessToken, refreshToken }).write();

    // Trả về thông tin người dùng và token
    const { password, accessToken: userAccessToken, refreshToken: userRefreshToken, ...userWithoutSensitiveInfo } = user;

    res.status(200).json({ user: userWithoutSensitiveInfo, accessToken, refreshToken });
  });
});

server.get("/users", authenticateToken, requireAdminRole, (req, res) => {
  let db = router.db; // lowdb instance

  let users = db.get("users").value(); // convert to array

  // Filter
  if (req.query.name) {
    users = users.filter((user) => user.name.includes(req.query.name));
  }

  // Search
  if (req.query.q) {
    users = users.filter((user) => user.name.includes(req.query.q));
  }

  // Sort
  if (req.query._sort && req.query._order) {
    users = _.orderBy(users, req.query._sort, req.query._order);
  }

  // Paginate
  const _page = req.query._page || 1;
  const _limit = req.query._limit || 10;
  const start = (_page - 1) * _limit;
  const end = _page * _limit;

  const paginatedUsers = users.slice(start, end);

  res.json({
    pagination: {
      total: users.length,
      page: _page,
      limit: _limit,
    },
    sort: {
      field: req.query._sort || "id",
      order: req.query._order || "asc",
    },
    data: paginatedUsers,
  });
});

server.get("/dashboard", (req, res) => {
  try {
    const employeeCount = router.db.get("employees").size().value();
    const projectCount = router.db.get("projects").size().value();
    const positionCount = router.db.get("positions").size().value();

    res.status(200).json({
      employeeCount,
      projectCount,
      positionCount,
    });
  } catch (err) {
    res.status(500).send(err);
  }
});

server.get("/employees", (req, res) => {
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
  const employeeId = req.params.id;

  const employee = router.db.get("employees").find({ id: employeeId }).value();

  if (!employee) {
    return res.status(404).json({ error: "Nhân viên không tồn tại" });
  }

  res.status(200).json(employee);
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

      const newEmploy = {
        id: uuidv4(),
        ...req.body,
        avatar: avatarUrl,
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
      .filter({ is_manager: true })
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
server.put("/employees/:id", upload.single("avatar"), async (req, res) => {
  try {
    const employeeId = req.params.id;
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

    const updatedEmployInDb = router.db
      .get("employees")
      .find({ id: employeeId })
      .assign(updatedEmploy)
      .write();

    res.status(200).json(updatedEmployInDb);
  } catch (err) {
    res.status(500).send(err);
  }
});

// Xóa một sản phẩm
server.delete(
  "/employees/:id",
  authenticateToken,
  requireAdminRole,
  (req, res) => {
    const employeeId = req.params.id;
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

server.use(router);
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
