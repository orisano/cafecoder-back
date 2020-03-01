CREATE DATABASE IF NOT EXISTS cafecoder;
USE cafecoder;

CREATE TABLE IF NOT EXISTS users(
    id varchar(32) NOT NULL,
    name varchar(100) NOT NULL,
    email varchar(255),
    password_hash varchar(64) NOT NULL,
    auth_token varchar(64),
    role varchar(10) NOT NULL,
    rate int,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS contests(
    id varchar(32) NOT NULL,
    name varchar(32) NOT NULL,
    start_time datetime NOT NULL,
    end_time datetime NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS problems(
    id varchar(32) NOT NULL,
    contest_id varchar(32) NOT NULL,
    name varchar(4) NOT NULL,
    point int,
    testcase_id varchar(32),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS code_sessions(
    id varchar(32) NOT NULL,
    problem_id varchar(32) NOT NULL,
    user_id varchar(32) NOT NULL,
    lang varchar(32) NOT NULL,
    upload_date datetime,
    result varchar(8), 
    error varchar(1024),
    PRIMARY KEY (id)
);
ALTER TABLE code_sessions ADD INDEX code_sessions_user_idx(user_id, upload_date);
ALTER TABLE code_sessions ADD INDEX code_sessions_problem_idx(problem_id, upload_date);
ALTER TABLE code_sessions ADD INDEX code_sessions_problem_user_idx(problem_id, user_id, upload_date);

CREATE TABLE IF NOT EXISTS testcases(
    id varchar(32) NOT NULL, 
    problem_id varchar(32) NOT NULL,
    listpath varchar(1024) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS testcase_results(
    id varchar(32) NOT NULL,
    session_id varchar(32) NOT NULL,
    name varchar(255) NOT NULL,
    result varchar(8),
    time int(11),
    PRIMARY KEY (id)
);
ALTER TABLE testcase_results ADD INDEX testcase_results_session_idx(session_id, time);
