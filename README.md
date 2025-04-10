# Auth Service - CheckInn PMS

Welcome to the **Auth Service** module of the CheckInn Property Management System (PMS) project. This is a **Spring Boot microservice** responsible for **user authentication and management**, including registration, login, profile updates, soft deletion, and JWT token generation. It is designed to be **stateless**, secure, and scalable for hotel system needs.

---

## ✨ Features

- User registration with role assignment
- Stateless authentication using JWT (JSON Web Tokens)
- Login with encrypted password validation
- Soft deletion (logical delete) for users
- Profile management (update name, role, password, and function)
- Role-based access control with Spring Security
- Unit tests with high coverage using JUnit 5 and Mockito
- Code coverage reporting

---

## 📄 Technologies Used

- **Java 21**
- **Spring Boot 3.4.4**
- **Spring Security**
- **JWT (io.jsonwebtoken)**
- **PostgreSQL** (database driver configured, but not required for tests)
- **Lombok**
- **JUnit 5**
- **Mockito**
- **JaCoCo** (code coverage)

---

## 👩‍💼 User Roles

- `ADMIN`: Full access to user list, update, delete, and manage roles.
- `USER`: Can access their profile and update limited fields (like name and password).

---

## ⚙️ Setup & Running the Application

### Prerequisites

- JDK 21
- Maven 3.9+

### Running

```bash
mvn spring-boot:run
```

By default, the application runs on `http://localhost:8080`

---

## ✉️ API Endpoints

| Endpoint | Method | Description | Auth Required |
|---------|--------|-------------|---------------|
| `/api/auth/register` | POST | Register a new user | No |
| `/api/auth/login` | POST | Login with email and password | No |
| `/api/auth/me` | GET | Get current user details | Yes |
| `/api/auth/users` | GET | List all users (admin only) | Yes (ADMIN) |
| `/api/auth/users/{id}` | PUT | Update user info | Yes |
| `/api/auth/users/{id}` | DELETE | Soft delete a user | Yes (ADMIN) |

---

## 🎮 Running Tests

This project includes comprehensive unit tests for services and utilities.

### To run tests:
```bash
mvn test
```

### To run tests with coverage:
```bash
mvn clean test jacoco:report
```

### To view coverage report:
Open the following file in your browser:
```
target/site/jacoco/index.html
```

You should see coverage metrics for:
- `AuthService`
- `AuthController`
- `JwtUtil`
- `JwtFilter`

---

## 🌐 Example JWT Payload

```json
{
  "sub": "1",
  "email": "admin@email.com",
  "role": "ADMIN",
  "iat": 1712719441,
  "exp": 1712723041
}
```

> The JWT is signed using a secret key defined in `application.properties`:
```properties
jwt.secret=your-secret-key
jwt.expiration=3600000
```

---

## 🔧 Environment Variables / Configuration

Update these in `application.properties`:
```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/checkinn
spring.datasource.username=youruser
spring.datasource.password=yourpassword
jwt.secret=your32charsecretkey1234567890123456
jwt.expiration=3600000
```

---

## 💼 License

This project is for **educational purposes only**, part of a hotel management system with microservice architecture.

---

## 🚀 What's Next

- Integration with other services: guests, bookings, invoices
- Deploy to Docker or cloud environment
- End-to-end tests with Testcontainers or MockMvc

---

