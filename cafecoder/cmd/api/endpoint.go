package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"

	"github.com/tachibana51/cafecoder-back/cafecoder"
)

type testcase struct {
	CaseName string `json:"testcase_name" db:"testcase_name"`
	Result   string `json:"result" db:"result"`
	Runtime  int    `json:"runtime" db:"runtime"`
}

//POST /api/v1/code
type reqPostCode struct {
	Code      string `json:"code"`
	Username  string `json:"username"`
	AuthToken string `json:"auth_token"`
	Problem   string `json:"problem"`
	Language  string `json:"language"`
	ContestID string `json:"contest_id"`
}

type resPostCode struct {
	CodeSession string `json:"code_session"`
}

//GET /api/v1/code
type reqGetCode struct {
	CodeSession string `json:"code_session"`
}
type resGetCode struct {
	Code string `json:"code"`
}

//GET /api/v1/result
type reqGetResult struct {
	CodeSession string `json:"code_session"`
	AuthToken   string `json:"auth_token"`
}

type resGetResult struct {
	Username     string `json:"username" db:"user_name"`
	ContestName  string `json:"contestname" db:"contest_name"`
	Problem      string `json:"problem" db:"problem_name"`
	Point        string `json:"point" db:"problem_point"`
	Language     string `json:"language" db:"language"`
	Result       string `json:"result" db:"result"`
	MaxRuntime   int    `json:"max_runtime" db:"max_runtime"`
	ErrorMessage string `json:"error" db:"error"`
}

//GET /api/v1/user
type reqGetUser struct {
	Username string `json:"username"`
}

type resGetUser struct {
	Result bool `json:"result"`
}

//POST /api/v1/user
type reqPostUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//GET /api/v1/submits
type submit struct {
	Username    string `json:"username" db:"user_name"`
	ProblemName string `json:"problem_name" db:"problem_name"`
	SubmitID    string `json:"submit_id" db:"submit_id"`
	SubmitTime  string `json:"submit_time" db:"submit_time"`
	Result      string `json:"result" db:"result"`
}

type reqGetSubmits struct {
	Username  string `json:"username"`
	ContestID string `json:"contest_id"`
}

type resGetSubmits struct {
	Submits []submit `json:"submits"`
}

//GET /api/v1/allsubmits

type reqGetAllSubmits struct {
	ContestID string `json:"contest_id"`
}

type resGetAllSubmits struct {
	Submits []submit `json:"submits"`
}

//POST /api/v1/auth
type reqPostAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type resPostAuth struct {
	Result bool   `json:"result"`
	Token  string `json:"auth_token"`
}

//GET /api/v1/contest
type reqGetContest struct {
	ContestID string `json:"contest_id"`
}

type resGetContest struct {
	ContestName string `json:"contest_name"`
	StartTime   string `json:"start_time"`
	EndTime     string `json:"end_time"`
	IsOver      bool   `json:"is_over"`
	IsOpen      bool   `json:"is_open"`
}

//GET /api/v1/all_contests
type resGetAllContests struct {
	Contests []resGetContest `json:"contests"`
}

//GET /api/v1/testcase
type reqGetTestCase struct {
	CodeSession string `json:"code_session"`
}

type resGetTestCase struct {
	TestCases []testcase `json:"testcases"`
}

//GET /api/v1/ranking
type firstAC struct {
	ProblemName string `json:"problem_name"`
	SubmitID    string `json:"submit_id"`
	SubmitTime  string `json:"submit_time"`
	Point       int    `json:"point"`

	submittedAt time.Time
}

type contestResult struct {
	Rank     int       `json:"rank"`
	Username string    `json:"username"`
	Submits  []firstAC `json:"submits"`
	Point    int       `json:"point"`
	lastAC   time.Time
}

type reqGetRanking struct {
	ContestID string `json:"contest_id"`
}

type Problem struct {
	ID         string `db:"id"`
	ContestID  string `db:"contest_id"`
	Name       string `db:"name"`
	Point      int    `db:"point"`
	TestcaseID string `db:"testcase_id"`
}

func main() {
	log.SetPrefix("api: ")
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	db, err := sqlx.Open("mysql", cafecoder.MySQLDBN)
	if err != nil {
		return xerrors.Errorf("open db: %w", err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(60 * time.Second)

	s := server{
		db: db,
	}

	http.HandleFunc("/api/v1/result", s.handleResult)
	http.HandleFunc("/api/v1/code", s.handleCode)
	http.HandleFunc("/api/v1/submits", s.handleSubmits)
	http.HandleFunc("/api/v1/allsubmits", s.handleAllSubmits)
	http.HandleFunc("/api/v1/testcase", s.handleTestcase)
	http.HandleFunc("/api/v1/user", s.handleUser)
	http.HandleFunc("/api/v1/auth", s.handleAuth)
	http.HandleFunc("/api/v1/contest", s.handleContest)
	http.HandleFunc("/api/v1/all_contests", s.handleAllContests))
	http.HandleFunc("/api/v1/ranking", s.handleRanking)
	return http.ListenAndServe(":8080", nil)
}

type server struct {
	db *sqlx.DB
}

func respondBadRequest(w http.ResponseWriter, req *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
}

func respondServiceUnavailable(w http.ResponseWriter, req *http.Request, err error) {
	w.WriteHeader(http.StatusServiceUnavailable)
}

func respondJSON(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

//api/v1/result

func (s *server) handleResult(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetResult
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		query := `
SELECT
	u.name user_name,
	c.name contest_name,
	p.name problem_name,
	p.point problem_point,
	cs.lang language,
	cs.result result,
	cs.error error,
	(SELECT MAX(tr.time) FROM testcase_results tr WHERE tr.session_id = ?) max_runtime
FROM 
    code_sessions cs
	INNER JOIN users u ON u.id = cs.user_id
	INNER JOIN problems p ON p.id = cs.problem_id
	INNER JOIN contests c ON c.id = p.contest_id
WHERE
	cs.id = ?
`
		var res resGetResult
		err := s.db.Get(&res, query, reqBody.CodeSession, reqBody.CodeSession)
		if err == sql.ErrNoRows {
			respondBadRequest(w, req, nil)
			return
		}
		if err != nil {
			respondServiceUnavailable(w, req, xerrors.Errorf("query result: %w", err))
			return
		}
		respondJSON(w, &res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//api/v1/code
func (s *server) handleCode(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		var reqBody reqPostCode
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		code, err := base64.StdEncoding.DecodeString(reqBody.Code)
		if err != nil {
			respondBadRequest(w, req, err)
			return
		}
		var userID string
		err = s.db.Get(&userID, "SELECT id FROM users WHERE name = ? AND auth_token = ?", reqBody.Username, reqBody.AuthToken)
		if err == sql.ErrNoRows {
			respondBadRequest(w, req, nil)
			return
		}
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}

		query := `
SELECT
	p.id problem_id,
	p.point problem_point,
	t.listpath testcase_path
FROM
	contests c
	INNER JOIN problems p ON p.contest_id = c.id
	INNER JOIN testcases t ON t.id = p.testcase_id 
WHERE
	c.id = ? AND p.name = ?
`
		var row struct {
			ProblemID    string `db:"problem_id"`
			ProblemPoint int    `db:"problem_point"`
			TestcasePath string `db:"testcase_path"`
		}
		err = s.db.Get(&row, query, reqBody.ContestID, reqBody.Problem)
		if err == sql.ErrNoRows {
			respondBadRequest(w, req, nil)
			return
		}
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		sessionID := uuid.New().String()
		filename := "/submits/" + userID + "_" + sessionID
		err = ioutil.WriteFile(filepath.Join("./fileserver", filename), code, 0666)
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		_, err = s.db.Exec("INSERT INTO code_sessions (id, problem_id, user_id, lang, result, upload_date) VALUES (?, ?, ?, ?, 'WJ', NOW())", sessionID, row.ProblemID, userID, reqBody.Language)
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		conn, err := net.Dial("tcp", cafecoder.QueHostPort)
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		_, err = fmt.Fprintf(conn, "dummy,%s,%s,%s,%s,%d", sessionID, filename, reqBody.Language, row.TestcasePath, row.ProblemPoint)
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		_ = conn.Close()
		res := resPostCode{CodeSession: sessionID}
		respondJSON(w, res)
		return
	case http.MethodGet:
		var reqBody reqGetCode
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		query := `SELECT u.id FROM code_sessions cs INNER JOIN users u ON u.id = cs.user_id WHERE cs.id = ?`
		var userID string
		err := s.db.Get(&userID, query, reqBody.CodeSession)
		if err == sql.ErrNoRows {
			respondBadRequest(w, req, nil)
			return
		}
		if err != nil {
			respondServiceUnavailable(w, req, xerrors.Errorf("query user: %w", err))
			return
		}
		filename := "/submits/" + userID + "_" + reqBody.CodeSession
		b, err := ioutil.ReadFile(filepath.Join("./fileserver", filename))
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		encodedCode := base64.StdEncoding.EncodeToString(b)
		res := resGetCode{Code: encodedCode}
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//api/v1/submits
func (s *server) handleSubmits(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetSubmits
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		query := `
SELECT
	u.name user_name,
	p.name problem_name,
	cs.id submit_id,
	cs.upload_date submit_time,
	cs.result result
FROM 
	contests c
	INNER JOIN problems p ON p.contest_id = c.id
	INNER JOIN code_sessions cs ON cs.problem_id = p.id
	INNER JOIN users u ON u.id = cs.user_id
WHERE
    u.name = ? AND c.id = ?
ORDER BY cs.upload_date DESC
`
		submits := []submit{}
		err := s.db.Select(&submits, query, reqBody.Username, reqBody.ContestID)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		var res resGetSubmits
		res.Submits = submits
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//api/v1/allsubmits
func (s *server) handleAllSubmits(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetAllSubmits
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		query := `
SELECT
    u.name user_name,
    p.name problem_name,
    cs.id submit_id,
    cs.upload_date submit_time,
    cs.result result
FROM 
	contests c
	INNER JOIN problems p ON p.contest_id = c.id
	INNER JOIN code_sessions cs ON cs.problem_id = p.id
	INNER JOIN users u ON u.id = cs.user_id
WHERE
    c.id = ? AND c.start_time < cs.upload_date
ORDER BY cs.upload_date DESC
`
		submits := []submit{}
		err := s.db.Select(&submits, query, reqBody.ContestID)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		var res resGetAllSubmits
		res.Submits = submits
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//api/v1/testcase
func (s *server) handleTestcase(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetTestCase
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		query := `
SELECT
	name testcase_name,
	result result,
	time runtime
FROM
	testcase_results
WHERE
	session_id=?
ORDER BY name
`
		caseList := []testcase{}
		err := s.db.Select(&caseList, query, reqBody.CodeSession)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		var res resGetTestCase
		res.TestCases = caseList
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//api/v1/user
func (s *server) handleUser(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetUser
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		query := `SELECT id FROM users WHERE name = ?`
		var userID string
		err := s.db.Get(&userID, query, reqBody.Username)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		result := userID != ""
		res := resGetUser{Result: result}
		respondJSON(w, res)
		return
	case http.MethodPost:
		var reqBody reqPostUser
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		query := `SELECT id FROM users WHERE name = ?`
		var userID string
		err := s.db.Get(&userID, query, reqBody.Username)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		if userID != "" {
			respondBadRequest(w, req, nil)
			return
		}
		userID = uuid.New().String()
		username := reqBody.Username
		passwordHash := cafecoder.GetHash(reqBody.Password)
		_, err = s.db.Exec("INSERT INTO users (id, name, password_hash, role) VALUES (?, ?, ?, 'user')", userID, username, passwordHash)
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		res := resGetUser{Result: true}
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//api/v1/auth
func (s *server) handleAuth(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		var reqBody reqPostAuth
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		hash := cafecoder.GetHash(reqBody.Password)
		var userID string
		err := s.db.Get(&userID, "SELECT id FROM users WHERE name = ? AND password_hash = ?", reqBody.Username, hash)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		var res resPostAuth
		res.Result = userID != ""
		res.Token = cafecoder.GetHash(uuid.New().String())
		if res.Result {
			_, err := s.db.Exec("UPDATE users SET auth_token = ? WHERE id = ?", res.Token, userID)
			if err != nil {
				respondServiceUnavailable(w, req, err)
				return
			}
		}
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//GET /api/v1/contest
func (s *server) handleContest(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetContest
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		var row struct {
			ContestName      string    `db:"name"`
			ContestStartTime time.Time `db:"start_time"`
			ContestEndTime   time.Time `db:"end_time"`
		}
		var contestName string
		err := s.db.Get(&row, "SELECT name, start_time, end_time FROM contests WHERE id = ?", reqBody.ContestID)
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		var res resGetContest
		res.ContestName = contestName

		var dbNow time.Time
		if err := s.db.Get(&dbNow, "SELECT NOW()"); err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}

		res.IsOpen = dbNow.After(row.ContestStartTime)
		res.IsOver = dbNow.After(row.ContestEndTime)
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

//GET /api/v1/all_contests
func (s *server) handleAllContests(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetContest
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}
		var rows []struct {
			ContestName      string    `db:"name"`
			ContestStartTime time.Time `db:"start_time"`
			ContestEndTime   time.Time `db:"end_time"`
		}
		err := s.db.Select(&rows, "SELECT name, start_time, end_time FROM contests ORDER BY start_time DESC")
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		var dbNow time.Time
		if err := s.db.Get(&dbNow, "SELECT NOW()"); err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		var res resGetAllContests
		res.Contests = make([]resGetContest, 0, len(rows))
		for _, row := range rows {
			res.Contests = append(res.Contests, resGetContest{
				ContestName: row.ContestName,
				StartTime:   row.ContestStartTime.Format(time.RFC3339),
				EndTime:     row.ContestEndTime.Format(time.RFC3339),
				IsOpen:      dbNow.After(row.ContestStartTime),
				IsOver:      dbNow.After(row.ContestEndTime),
			})
		}
		respondJSON(w, res)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (s *server) handleRanking(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var reqBody reqGetRanking
		if err := json.NewDecoder(req.Body).Decode(&reqBody); err != nil {
			respondBadRequest(w, req, err)
			return
		}

		// 1. コンテスト中の提出でACになっている問題の一覧をユーザIDごとに抽出する
		// 2. 1.ごとにユーザ名の取得をする
		// 3. 1.ごとに提出の中で一番最初のsession idを取得する
		// 4. 3.の実際の提出日時を取得する
		// 5. 1.ごとに問題の点数を取得する

		var contest struct {
			ID        string    `db:"id"`
			Name      string    `db:"name"`
			StartTime time.Time `db:"start_time"`
			EndTime   time.Time `db:"end_time"`
		}
		err := s.db.Get(&contest, "SELECT * FROM contests WHERE id = ?", reqBody.ContestID)
		if err != sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			respondServiceUnavailable(w, req, err)
			return
		}
		var problems []*Problem
		err = s.db.Select(&problems, "SELECT * FROM problems WHERE contest_id = ?", contest.ID)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		problemByID := make(map[string]*Problem)
		problemIDs := make([]string, 0, len(problems))
		for _, p := range problems {
			problemByID[p.ID] = p
			problemIDs = append(problemIDs, p.ID)
		}
		var accepts []struct {
			UserID       string `db:"user_id"`
			ProblemID    string `db:"problem_id"`
			UploadDateID string `db:"upload_date_id"`
		}
		query, args, err := sqlx.In(`
SELECT
	user_id,
    problem_id,
    MIN(CONCAT(upload_date, '$', id)) upload_date_id
FROM
	code_sessions
WHERE
	problem_id IN (?)
	AND upload_date BETWEEN ? AND ?
	AND result = 'AC'
GROUP BY problem_id, user_id
`, problemIDs, contest.StartTime, contest.EndTime)
		if err != nil {
			panic(err)
		}
		err = s.db.Select(&accepts, query, args...)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}
		acceptsByUserID := make(map[string][]firstAC)
		for _, accept := range accepts {
			problem := problemByID[accept.ProblemID]
			userID := accept.UserID
			tokens := strings.SplitN(accept.UploadDateID, "$", 2)
			uploadTime, _ := time.Parse("2006-01-02 15:04:05", tokens[0])
			submitID := tokens[1]

			submitSeconds := uploadTime.Sub(contest.StartTime) / time.Second
			sec := submitSeconds % 60
			min := submitSeconds / 60 % 60
			hour := submitSeconds / 3600

			acceptsByUserID[userID] = append(acceptsByUserID[userID], firstAC{
				ProblemName: problem.Name,
				SubmitID:    submitID,
				SubmitTime:  fmt.Sprint(hour, ":", min, ":", sec),
				Point:       problem.Point,

				submittedAt: uploadTime,
			})
		}

		var contestants []struct {
			UserID   string `db:"user_id"`
			Username string `db:"user_name"`
		}
		query, args, err = sqlx.In(`
SELECT DISTINCT 
	u.id user_id,
    u.name user_name
FROM
	code_sessions cs
	INNER JOIN users u ON cs.user_id = u.id
WHERE
	cs.problem_id IN (?)
	AND cs.upload_date BETWEEN ? AND ? 
	AND cs.result = 'AC'
`, problemIDs, contest.StartTime, contest.EndTime)
		if err != nil {
			panic(err)
		}
		err = s.db.Select(&contestants, query, args...)
		if err != nil && err != sql.ErrNoRows {
			respondServiceUnavailable(w, req, err)
			return
		}

		// ユーザごとの得点を取得する
		// ユーザの最終新規AC時刻を取得する
		// 得点の降順, 最終新規AC時刻の昇順にする
		var results []contestResult
		for _, contestant := range contestants {
			result := contestResult{
				Username: contestant.Username,
				Submits:  acceptsByUserID[contestant.UserID],
			}
			result.lastAC = result.Submits[0].submittedAt
			for _, submit := range result.Submits {
				result.Point += submit.Point
				if result.lastAC.Before(submit.submittedAt) {
					result.lastAC = submit.submittedAt
				}
			}
			results = append(results, result)
		}
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].Point != results[j].Point {
				return results[i].Point > results[j].Point
			}
			return results[i].lastAC.Before(results[j].lastAC)
		})
		respondJSON(w, results)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
