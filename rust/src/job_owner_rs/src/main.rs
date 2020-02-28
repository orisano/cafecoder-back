#[macro_use]
extern crate mysql;
extern crate serde;
extern crate serde_json;
use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use std::str;
use mysql as my;
use serde::{Serialize, Deserialize};

//todo config struct
static JUDGE_HOST_PORT: &'static str = env!("JUDGE_HOST_PORT");
static JUDGE_MAX : &'static str = env!("JUDGE_MAX");
//job map<job, num>
struct MutexJobMap {
    mutex_job_map : Mutex<HashMap<String, Vec<u8>>>,
}

impl MutexJobMap {
    fn new() -> MutexJobMap {
        MutexJobMap {
            mutex_job_map : Mutex::new(HashMap::new())
        }
    }
}

//json
#[derive(Serialize, Deserialize)]
struct Testcase {
    name : String,
    result: String,
    memory_used: i64,
    time: i64,
}

#[derive(Serialize, Deserialize)]
struct OverAllResult {
    session_id : String,
    over_all_time : i64,
    over_all_result : String,
    over_all_score : i64,
    err_message : String,
    testcases : Vec<Testcase>,
}

fn read_data_stream(mut stream: &TcpStream) -> [u8; 1024] {
    let mut data = [0 as u8; 1024];
    match stream.read(&mut data) {
        Err(err) => println!("tcp read Error: {}", err) ,
        _ => (),
    }
    data
}

//dial tcp
fn pass_to_judge (data : &[u8]) -> Result<usize, std::io::Error> {
    TcpStream::connect(JUDGE_HOST_PORT)?.write(data)
}

//4649port
fn handle_for_api_rq<T>(stream: TcpStream, a_m_jobmap : Arc<T>) -> Result<String, String> {
    let data = read_data_stream(&stream);
    let req_csv : Vec<&str> = str::from_utf8(&data).unwrap_or(&"None".to_owned()).split(',').collect();
    //deside judge or que
    Arc::try_unwrap(a_m_jobmap).lock();
    match pass_to_judge(&data) {
        Err(_err) => Err("pass judge write Error".to_owned()),
        _ => Ok("4649 ok".to_owned())
    }
}

//5963port
fn handle_for_judge_rq(stream: TcpStream) {
    let data = read_data_stream(&stream);
}

fn main() {
    let mut children = vec![];
    let m_jobmap  = Arc::new(MutexJobMap::new());
    //spawn api thread
    children.push(thread::spawn(move|| {
        let listener_from_api = TcpListener::bind("0.0.0.0:4649").unwrap();
        for stream in listener_from_api.incoming() {
            let a_m_jobmap = Arc::clone(&m_jobmap);
            thread::spawn(|| {
                println!("{:?}", handle_for_api_rq(stream.unwrap(), a_m_jobmap).unwrap_or("4649 err".to_owned()));
            });
        }
    }));
    // spawn judge thread
    children.push(thread::spawn(move|| {
        let listener_from_judge = TcpListener::bind("0.0.0.0:5963").unwrap();
        for stream in listener_from_judge.incoming() {
            thread::spawn(move|| {
                handle_for_judge_rq(stream.unwrap())
            });
        }
    }));

    for child in children {
        let _ = child.join();
    }
}
