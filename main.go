package main

import (
	"ass_go/connect"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

type jwtCustomClaims struct {
	UserID   int64
	Username string
	jwt.RegisteredClaims
}

type Users struct {
	Id                           int
	Name, Email, HashPwd, Author string
}
type LogEndSess struct {
	Name    string
	LogSess bool
}

var loginsession = LogEndSess{}

func main() {
	e := echo.New()
	// Middleware

	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 5 * time.Second,
	}))
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))

	//middleware jwt token

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	// Restricted group

	// connection in database func
	connect.DbConection()

	// route
	e.GET("/", Home)
	// register route
	e.GET("/register", FormRegister)
	e.POST("/form-register", Registrasi)
	// login route
	e.GET("/login", FormLogin)
	e.POST("/valid-form", Login)

	// logoutsession
	e.POST("/logout", LogoutSession)
	r := e.Group("/")

	// Configure middleware with the custom claims type
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(jwtCustomClaims)
		},
		SigningKey: []byte("secret"),
	}
	r.Use(echojwt.WithConfig(config))

	e.Logger.Fatal(e.Start("localhost:3000"))
}

func createToken(userID int64, userEmail, secretKey string) (string, error) {

	// Membuat klaim JWT, termasuk klaim kustom
	claims := &jwtCustomClaims{
		UserID:   userID,
		Username: userEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}

	// Membuat token dengan klaim dan kunci rahasia
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Home(c echo.Context) error {
	token, err := c.Cookie("jwt")
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "missing or malformed jwt"})
	}

	sess, _ := session.Get("cookie", c)

	// Ambil nilai Iduser dari session
	IduserInterface := sess.Values["id"]

	if IduserInterface == nil {
		// Jika Iduser belum ada di dalam session, mungkin user belum login atau sesi telah berakhir
		// ridirect
		return c.JSON(http.StatusOK, nil)
	}
	//konversi menjadi integer
	Iduser := sess.Values["id"].(int)
	if IduserInterface == nil {

		return c.JSON(http.StatusOK, nil)
	}
	var user = Users{}

	connect.Conn.QueryRow(context.Background(), "SELECT id,name,email FROM tb_users WHERE id=$1", Iduser).Scan(&user.Id, &user.Name, &user.Email)

	loginsession := GetLoginSession(c)

	Data := map[string]interface{}{
		"Loginsession": loginsession,
		"Token":        token,
	}

	return c.JSON(http.StatusOK, Data)
}

//Validation login

func FormLogin(c echo.Context) error {

	sess, errsess := session.Get("cookie", c)
	if errsess != nil {
		return c.JSON(http.StatusInternalServerError, errsess.Error())
	}
	Flashes := map[string]interface{}{
		"message": sess.Values["message"],
		"alert":   sess.Values["alert"],
	}
	delete(sess.Values, "message")
	delete(sess.Values, "alert")

	sess.Save(c.Request(), c.Response())

	return c.JSON(http.StatusOK, Flashes)
}

func Login(c echo.Context) error {

	inputEmail := c.FormValue("inputEmail")
	inputPassword := c.FormValue("inputPassword")
	fmt.Println(inputEmail)
	fmt.Println(inputPassword)
	users := Users{}

	QuerLogerr := connect.Conn.QueryRow(context.Background(), "SELECT id, name, email,password FROM tb_users WHERE email=$1", inputEmail).Scan(&users.Id, &users.Name, &users.Email, &users.HashPwd)

	if QuerLogerr != nil {
		return FlashMessage(c, "Masukan Email/Password terlebih dahulu!!", false, "/login")
	}

	Comperr := bcrypt.CompareHashAndPassword([]byte(users.HashPwd), []byte(inputPassword))
	if Comperr != nil {
		return FlashMessage(c, "Email/Password Salah!!", false, "/login")
	}

	// Generate JWT token
	token, err := createToken(int64(users.Id), users.Email, "secret")
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating token")
	}
	fmt.Println("Token:", token)

	// Simpan token di cookie
	cookie := new(http.Cookie)
	cookie.Name = "jwt"
	cookie.Value = token
	cookie.Expires = time.Now().Add(24 * time.Hour)
	c.SetCookie(cookie)

	//simpan cookie session
	sess, _ := session.Get("cookie", c)
	sess.Options.MaxAge = 10800 //per/detik
	sess.Values["name"] = users.Name
	sess.Values["email"] = users.Email
	sess.Values["id"] = users.Id
	sess.Values["login"] = true
	sess.Save(c.Request(), c.Response())

	// Tunggu sebentar untuk memberi waktu pada goroutine untuk menyelesaikan tindakannya
	time.Sleep(1 * time.Second)

	return c.Redirect(http.StatusMovedPermanently, "/")

}

//register

func FormRegister(c echo.Context) error {

	sess, errsess := session.Get("cookie", c)
	if errsess != nil {
		return c.JSON(http.StatusInternalServerError, errsess.Error())
	}
	Flashes := map[string]interface{}{
		"message": sess.Values["message"],
		"alert":   sess.Values["alert"],
	}
	delete(sess.Values, "message")
	delete(sess.Values, "alert")

	sess.Save(c.Request(), c.Response())

	return c.JSON(http.StatusOK, Flashes)
}
func Registrasi(c echo.Context) error {
	InputName := c.FormValue("inputName")
	inputEmail := c.FormValue("inputEmail")
	inputPassword := c.FormValue("inputPassword")
	//Trim Auth
	// Lakukan validasi data input
	if inputPassword == "" || InputName == "" || inputEmail == "" {
		return FlashMessage(c, "inputkan terlebih dahulu !!", false, "/register")
	}
	// Hapus spasi putih di awal atau akhir string
	trimmedInput := strings.TrimSpace(inputPassword)

	// Pengecekan panjang data
	if len(trimmedInput) < 5 || len(trimmedInput) > 20 {
		return FlashMessage(c, "Registrasi Gagal ! Masukan Password 5 hingga 20 karakter", false, "/register")
	}

	//bcrypt hashing
	hashiteration, hasherr := bcrypt.GenerateFromPassword([]byte(inputPassword), 10)
	if hasherr != nil {
		return c.JSON(http.StatusInternalServerError, hasherr.Error())
	}

	QueryUser, QueryErr := connect.Conn.Exec(context.Background(), "INSERT INTO tb_users(name,email,password)VALUES($1,$2,$3)", InputName, inputEmail, hashiteration)

	// Cookie store

	fmt.Println("register berhasil :", QueryUser.RowsAffected())

	if QueryErr != nil {
		return c.JSON(http.StatusInternalServerError, hasherr.Error())
	}

	return FlashMessage(c, "Registerasi Berhasil Silahkan Login :", true, "/login")

}

func LogoutSession(c echo.Context) error {
	sess, _ := session.Get("cookie", c)

	sess.Options.MaxAge = -1
	sess.Save(c.Request(), c.Response())

	return FlashMessage(c, "logout berhasil", true, "/")
}

// function session Store
func FlashMessage(c echo.Context, message string, alert bool, redirectPath string) error {
	sess, errsess := session.Get("cookie", c)
	if errsess != nil {
		return c.JSON(http.StatusInternalServerError, errsess.Error())
	}
	sess.Values["message"] = message
	sess.Values["alert"] = alert
	sess.Save(c.Request(), c.Response())

	return c.Redirect(http.StatusMovedPermanently, redirectPath)
}

// Fungsi untuk mengambil data dari session dan membuat data untuk template
func GetLoginSession(c echo.Context) LogEndSess {
	sess, _ := session.Get("cookie", c)
	loginsession := LogEndSess{}

	if sess.Values["login"] != true {
		loginsession.LogSess = false
	} else {
		loginsession.LogSess = true
		loginsession.Name = sess.Values["name"].(string)
	}

	return loginsession
}
