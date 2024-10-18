package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"
	"strconv"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/go-sql-driver/mysql"
)

// User represents a bank user
type User struct {
	ID       int     `json:"id"`
	Username string  `json:"username"`
	Password string  `json:"-"`
	Balance  float64 `json:"balance"`
}

// Transaction represents a bank transaction
type Transaction struct {
    ID          int       `json:"id"`
    UserID      int       `json:"user_id"`
    FromUserID  *int      `json:"from_user_id,omitempty"`
    ToUserID    *int      `json:"to_user_id,omitempty"`
    Amount      float64   `json:"amount"`
    Type        string    `json:"type"`
    Timestamp   time.Time `json:"timestamp"`
}

type TransferRequest struct {
	ToUsername string  `json:"to_username"`
	Amount     float64 `json:"amount"`
}

// JwtCustomClaims represents custom claims for JWT
type JwtCustomClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

// Valid implements the jwt.Claims interface
func (j *JwtCustomClaims) Valid() error {
	if j.ExpiresAt != nil {
		if time.Now().Unix() > j.ExpiresAt.Unix() {
			return fmt.Errorf("token has expired")
		}
	}
	return nil
}

var db *sql.DB

const jwtSecret = "your-secret-key"

func main() {
	// Initialize database connection
	var err error
	db, err = sql.Open("mysql", "root:None@tcp(192.168.11.104:3306)/bank_app")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	app := echo.New()

	// Middleware
	app.Use(middleware.Logger())
	app.Use(middleware.Recover())

	// Routes
	app.POST("/login", handleLogin)
	app.POST("/register", handleRegister)

	// Protected routes
	r := app.Group("/api")
		// Configure middleware with the custom claims type
		config := echojwt.Config{
			NewClaimsFunc: func(c echo.Context) jwt.Claims {
				return new(JwtCustomClaims)
			},
			SigningKey: []byte(jwtSecret),
		}
		r.Use(echojwt.WithConfig(config))

	// r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
	// 	Claims:     &JwtCustomClaims{},
	// 	SigningKey: []byte(jwtSecret),
	// }))
	r.GET("/balance", getBalance)
	r.POST("/deposit", handleDeposit)
	r.POST("/withdraw", handleWithdraw)
	r.GET("/transactions", getTransactions)
	r.POST("/transfer", handleTransfer)

	app.Start(":9999")
}

func handleTransfer(c echo.Context) error {
    fromUserID := getUserIDFromToken(c)
    
    var req TransferRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request"})
    }

    // Validate amount
    if req.Amount <= 0 {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid amount"})
    }

    // Start a transaction
    tx, err := db.Begin()
    if err != nil {
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to start transaction"})
    }
    defer tx.Rollback()

    // Get the recipient's user ID
    var toUserID int
    err = tx.QueryRow("SELECT id FROM users WHERE username = ?", req.ToUsername).Scan(&toUserID)
    if err != nil {
        if err == sql.ErrNoRows {
            return c.JSON(http.StatusNotFound, echo.Map{"error": "Recipient not found"})
        }
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to fetch recipient information"})
    }

    // Check if sender is trying to transfer to themselves
    if fromUserID == toUserID {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Cannot transfer to yourself"})
    }

    // Check if sender has sufficient balance
    var fromBalance float64
    err = tx.QueryRow("SELECT balance FROM users WHERE id = ? FOR UPDATE", fromUserID).Scan(&fromBalance)
    if err != nil {
        if err == sql.ErrNoRows {
            return c.JSON(http.StatusNotFound, echo.Map{"error": "Sender account not found"})
        }
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to fetch sender balance"})
    }

    if fromBalance < req.Amount {
        return c.JSON(http.StatusBadRequest, echo.Map{"error": "Insufficient funds"})
    }

    // Update sender's balance
    _, err = tx.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", req.Amount, fromUserID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to update sender balance"})
    }

    // Update recipient's balance
    _, err = tx.Exec("UPDATE users SET balance = balance + ? WHERE id = ?", req.Amount, toUserID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to update recipient balance"})
    }

    // Record the transaction
    _, err = tx.Exec("INSERT INTO transactions (user_id, from_user_id, to_user_id, amount, type) VALUES (?, ?, ?, ?, 'transfer')", fromUserID, fromUserID, toUserID, req.Amount)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to record transaction"})
    }

    // Commit the transaction
    err = tx.Commit()
    if err != nil {
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to commit transaction"})
    }

    return c.JSON(http.StatusOK, echo.Map{
        "message": "Transfer successful",
        "amount":  req.Amount,
        "to":      req.ToUsername,
    })
}

func getTransactions(c echo.Context) error {
    userID := getUserIDFromToken(c)
    rows, err := db.Query(`
        SELECT id, user_id, from_user_id, to_user_id, amount, type, timestamp 
        FROM transactions 
        WHERE user_id = ? OR from_user_id = ? OR to_user_id = ? 
        ORDER BY timestamp DESC`, userID, userID, userID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to fetch transactions"})
    }
    defer rows.Close()

    transactions := []Transaction{}
    for rows.Next() {
        var t Transaction
        var fromUserID, toUserID sql.NullInt64
        var timestamp sql.NullString
        err := rows.Scan(&t.ID, &t.UserID, &fromUserID, &toUserID, &t.Amount, &t.Type, &timestamp)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to scan transaction"})
        }
        if fromUserID.Valid {
            fuid := int(fromUserID.Int64)
            t.FromUserID = &fuid
        }
        if toUserID.Valid {
            tuid := int(toUserID.Int64)
            t.ToUserID = &tuid
        }
        if timestamp.Valid {
            parsedTime, err := time.Parse("2006-01-02 15:04:05", timestamp.String)
            if err != nil {
                return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to parse timestamp"})
            }
            t.Timestamp = parsedTime
        }
        transactions = append(transactions, t)
    }

    return c.JSON(http.StatusOK, transactions)
}


func handleLogin(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	var user User
	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Password)
	if err != nil || user.Password != password {
		return echo.ErrUnauthorized
	}

	claims := &JwtCustomClaims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"access_token": t,
	})
}

func handleRegister(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Username already exists"})
	}

	return c.JSON(http.StatusCreated, echo.Map{"message": "User created successfully"})
}

func getBalance(c echo.Context) error {
	userID := getUserIDFromToken(c)
	var balance float64
	err := db.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&balance)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, echo.Map{"balance": balance})
}

func handleDeposit(c echo.Context) error {
	return handleTransaction(c, "deposit")
}

func handleWithdraw(c echo.Context) error {
	return handleTransaction(c, "withdrawal")
}

func handleTransaction(c echo.Context, transactionType string) error {
	userID := getUserIDFromToken(c)
	amount := c.FormValue("amount")

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var balance float64
	err = tx.QueryRow("SELECT balance FROM users WHERE id = ? FOR UPDATE", userID).Scan(&balance)
	if err != nil {
		return echo.ErrNotFound
	}

	if transactionType == "withdrawal" {
		if balance < parseFloat(amount) {
			return c.JSON(http.StatusBadRequest, echo.Map{"error": "Insufficient funds"})
		}
		balance -= parseFloat(amount)
	} else {
		balance += parseFloat(amount)
	}

	_, err = tx.Exec("UPDATE users SET balance = ? WHERE id = ?", balance, userID)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO transactions (user_id, amount, type) VALUES (?, ?, ?)", userID, amount, transactionType)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{"message": fmt.Sprintf("%s successful", transactionType), "new_balance": balance})
}




func getUserIDFromToken(c echo.Context) int {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*JwtCustomClaims)
	return claims.UserID
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}