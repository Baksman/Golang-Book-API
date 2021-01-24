package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// note this should be in  your .env file
var secretKey []byte = []byte("testingsecretkey")

type Db struct {
	collection *mgo.Collection
}

type BookDb struct {
	collection *mgo.Collection
}

type User struct {
	ID       string `json:"id" bson:"_id"`
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

type Book struct {
	ID      string   `json:"id" bson:"_id"`
	Title   string   `json:"title" bson:"title"`
	Authors []string `json:"authors" bson:"authors"`
	// Education Education `json:"education" bson:"education"`
}

func (b Book) String() {
	fmt.Println(b.ID)
}

func (b *BookDb) getAllBooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString, err := request.HeaderExtractor{"access_token"}.ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected sign in method %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		fmt.Println(token)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
		return
	}
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var books []Book

		err = b.collection.Find(bson.M{}).All(&books)
		print(books)
		print(books)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}
		marshaledBody, err := json.Marshal(books)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error occured while marshaling"))
			return
		}
		w.Write(marshaledBody)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)

	}
}
func (b *BookDb) addBook(w http.ResponseWriter, r *http.Request) {

	successResponse := map[string]interface{}{"success": true, "message": "added"}
	w.Header().Set("Content-Type", "application/json")
	tokenString, err := request.HeaderExtractor{"access_token"}.ExtractToken(r)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected sign in method %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		fmt.Println(token)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var book Book
		// if == http.NoBody(){
		_ = claims
		// 	w.Write([]byte("body is required"))
		// 	w.WriteHeader(http.StatusForbidden)
		// return

		pBody, err := ioutil.ReadAll(r.Body)
		json.Unmarshal(pBody, &book)

		if err != nil {
			w.Write([]byte("Error occured while unmarshaling try again"))
			w.WriteHeader(http.StatusNotFound)
			return
		}
		uuid, _ := uuid.NewV4()
		id := uuid.String()
		book.ID = id
		err = b.collection.Insert(book)
		// print(err.Error())
		// print(err.Error())
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Erorr parsing inserting object into mongodb"))
			return
		}
		w.WriteHeader(http.StatusOK)

		resp, err := json.Marshal(successResponse)
		w.Write(resp)

	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
	}

	// err = db.collection.Find(bson.M{"username": user.Username}).One(&fetchedUser)
	if err != nil {
		fmt.Println(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not found"))
		return
	}

}
func (db *Db) createUser(w http.ResponseWriter, r *http.Request) {
	user := User{}
	w.Header().Set("Content-Type", "application/json")
	pBody, err := ioutil.ReadAll(r.Body)
	json.Unmarshal(pBody, &user)
	uuid, _ := uuid.NewV4()
	id := uuid.String()
	fmt.Println(user.Password)
	fmt.Println(user.Username)
	bytes, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	user.ID = id
	user.Password = string(bytes)

	err = db.collection.Insert(user)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	response := map[string]string{"status": "success", "message": "you can now login via login route"}
	// response := Response{Token: tokenString, Status: "success"}
	responseJSON, _ := json.Marshal(response)
	w.WriteHeader(http.StatusOK)

	w.Write(responseJSON)
}

func (db *Db) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	user := User{}
	pBody, err := ioutil.ReadAll(r.Body)
	json.Unmarshal(pBody, &user)
	fetchedUser := User{}
	err = db.collection.Find(bson.M{"username": user.Username}).One(&fetchedUser)
	if err != nil {

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("User not found"))
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(fetchedUser.Password), []byte(user.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Incorrect password"))
		return
	}
	claims := jwt.MapClaims{
		"username":  user.Username,
		"ExpiresAt": time.Now().Add(time.Hour * 24),
		"IssuedAt":  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)

		w.Write([]byte(err.Error()))
		return

	}
	response := map[string]string{"status": "success", "Token": tokenString, "id": fetchedUser.ID}
	// response := Response{Token: tokenString, Status: "success"}
	responseJSON, _ := json.Marshal(response)
	w.WriteHeader(http.StatusOK)

	w.Write([]byte(responseJSON))
}

func main() {
	db := &Db{}
	bookdb := &BookDb{}
	var err error
	session, err := mgo.Dial("127.0.0.1:27017")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer session.Close()
	db.collection = session.DB("usersapi").C("userprofile")
	bookdb.collection = session.DB("books").C("all_books")
	r := mux.NewRouter()
	r.HandleFunc("/login", db.login).Methods("POST")
	r.HandleFunc("/sign-up", db.createUser).Methods("POST")
	r.HandleFunc("/add-book", bookdb.addBook).Methods("POST")
	r.HandleFunc("/get-allbooks", bookdb.getAllBooks).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", r))
}
