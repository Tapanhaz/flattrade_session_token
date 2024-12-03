use libotp::totp;
use sha2::{Sha256, Digest};
use lazy_static:: lazy_static;
use url::{Url, form_urlencoded};
use serde::{Deserialize, Serialize};
use std::{collections:: HashMap, str::FromStr, ffi::{CString, CStr}};
use reqwest::{header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, HOST, ORIGIN, REFERER}, blocking:: Client};

const FLATTRADE_HOST: &str = "https://auth.flattrade.in";
const API_HOST: &str = "https://authapi.flattrade.in";

lazy_static! {
    static ref ROUTES: HashMap<&'static str, String> = {
        let mut map = HashMap::new();
        map.insert("session", format!("{}/auth/session", API_HOST));
        map.insert("ftauth", format!("{}/ftauth", API_HOST));
        map.insert("apitoken", format!("{}/trade/apitoken", API_HOST));
        map
    };
}

lazy_static! {
    static ref HEADERS: HeaderMap = {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
        headers.insert(HOST, HeaderValue::from_static("authapi.flattrade.in"));
        headers.insert(ORIGIN, HeaderValue::from_str(FLATTRADE_HOST).unwrap()); 
        headers.insert(REFERER, HeaderValue::from_str(&format!("{}/", FLATTRADE_HOST)).unwrap()); 
        headers
    };
}

#[derive(Debug, Serialize, Deserialize)]
struct CRED {
    user: String,
    password: String,
    totp_key: String,
    enctoken: String,
    api_key: String,
    api_secret: String
}

#[derive(Serialize)]
struct AuthJson {
    #[serde(rename = "UserName")]
    user_name: String,
    
    #[serde(rename = "Password")]
    password: String,
    
    #[serde(rename = "App")]
    app: String,
    
    #[serde(rename = "ClientID")]
    client_id: String,
    
    #[serde(rename = "Key")]
    key: String,
    
    #[serde(rename = "APIKey")]
    api_key: String,
    
    #[serde(rename = "PAN_DOB")]
    pan_dob: String,
    
    #[serde(rename = "Sid")]
    sid: String,
    
    #[serde(rename = "Override")]
    override_field: String, 
}

#[derive(Serialize)]
struct AuthTokenJson {
    api_key: String,
    request_code: String, 
    api_secret: String
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    #[serde(rename = "RedirectURL")]
    redirect_url: Option<String>,
    emsg: Option<String>
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[allow(dead_code)]
    client: String,

    #[allow(dead_code)]
    emsg: String,

    #[allow(dead_code)]
    stat: String,

    token: Option<String>
}

fn encode_item(item: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(item.as_bytes()); 

    let result = hasher.finalize();
    let encoded_item = format!("{:x}", result); 
    
    encoded_item
}

fn generate_otp(totp_key: &str) -> String {
    let otp = totp(totp_key, 6, 30, 0).unwrap();
    let padded_otp = format!("{:06}", otp);
    println!("Generated OTP: {:?}", padded_otp);
    padded_otp
}


#[no_mangle]
pub extern "C" fn get_session_token(
                user: *const i8,
                password: *const i8,
                totp_key: *const i8,
                api_key: *const i8,
                api_secret: *const i8,
                verbose: i8
            ) -> *mut i8 {
    let user_str: String;
    let password_str: String;
    let totp_key_str: String;
    let api_key_str: String;
    let api_secret_str: String;
    let verbose_flag: bool = verbose != 0;
            
    unsafe {
        user_str = CStr::from_ptr(user).to_str().unwrap_or("").to_string();
        password_str = CStr::from_ptr(password).to_str().unwrap_or("").to_string();
        totp_key_str = CStr::from_ptr(totp_key).to_str().unwrap_or("").to_string();
        api_key_str = CStr::from_ptr(api_key).to_str().unwrap_or("").to_string();
        api_secret_str = CStr::from_ptr(api_secret).to_str().unwrap_or("").to_string();
    }


    if let Ok(client) = Client::builder()
                        .default_headers(HEADERS.clone())
                        .cookie_store(true)
                        .build() {
            
            match ROUTES.get("session") {
                Some(session_url) => {
                    match client.post(session_url).send() {
                        Ok(response) => {
                            let sid: String = response.text().unwrap();

                            let auth_payload: AuthJson = AuthJson {
                                user_name: user_str.clone(),
                                password: encode_item(&password_str),
                                app: "".to_string(),
                                client_id: "".to_string(),
                                key: "".to_string(),
                                api_key: api_key_str.clone(), //api_key_str.clone(),
                                pan_dob: generate_otp(&totp_key_str),
                                sid: sid.to_string(),
                                override_field: "".to_string()     
                                };
                            
                            match ROUTES.get("ftauth") {
                                Some(auth_url) => {
                                    match client.post(auth_url)
                                                .json(&auth_payload)
                                                .send() {
                                        Ok(response) => {
                                            let mut auth_json: AuthResponse = match response.json() {
                                                Ok(json) => json,
                                                Err(err) => {
                                                    eprintln!("Error in intial auth request :: {}", err);
                                                    return std::ptr::null_mut();
                                                }
                                            };

                                            if verbose_flag {
                                                println!("AUTH RESPONSE 1 :: {:?}", &auth_json);
                                            };
                                            
                                            if let Some(emsg_str) = auth_json.emsg.as_deref() {
                                                if emsg_str == "DUPLICATE" {
                                                    println!("Duplicate auth request. Retrying...");
                                                    let second_auth_payload = AuthJson {
                                                        user_name: user_str.clone(),
                                                        password: encode_item(&password_str),
                                                        app: "".to_string(),
                                                        client_id: "".to_string(),
                                                        key: "".to_string(),
                                                        api_key: encode_item(&api_key_str), 
                                                        pan_dob: generate_otp(&totp_key_str),
                                                        sid: sid.to_string(),
                                                        override_field: "Y".to_string()     
                                                        };

                                                        match ROUTES.get("ftauth") {
                                                            Some(auth_url) => {
                                                                match client.post(auth_url)
                                                                            .json(&second_auth_payload)
                                                                            .send() {
                                                                                Ok(response) => {
                                                                                    auth_json = match response.json() {
                                                                                        Ok(json) => json,
                                                                                        Err(err) => {
                                                                                            eprintln!("Error in second auth request :: {}", err);
                                                                                            return std::ptr::null_mut();
                                                                                        }
                                                                                    };

                                                                                    if verbose_flag {
                                                                                        println!("AUTH RESPONSE 2 :: {:?}", &auth_json);
                                                                                    };

                                                                                    if let Some(emsg_str) = auth_json.emsg.as_deref() {
                                                                                        if emsg_str.is_empty() {
                                                                                            {}
                                                                                            //return std::ptr::null_mut();
                                                                                        } else {
                                                                                            eprintln!("Error in second auth response :: {}", emsg_str);
                                                                                            return std::ptr::null_mut();
                                                                                        }
                                                                                    } else {
                                                                                    eprintln!("emsg not found in second auth response");
                                                                                    return std::ptr::null_mut();
                                                                                    }
                                                                                }
                                                                                Err(err) => {
                                                                                    eprintln!("Error in second auth response :: {}", err);
                                                                                    return std::ptr::null_mut();
                                                                                }
                                                                            }
                                                            }
                                                            None => {
                                                                eprintln!("Auth url not found.");
                                                                return std::ptr::null_mut();
                                                            }
                                                        }
                                                        
                                                } else if emsg_str.is_empty(){
                                                    {}
                                                    //return std::ptr::null_mut();
                                                } else {
                                                    eprintln!("Error in auth response :: {}", emsg_str);
                                                    return std::ptr::null_mut();
                                                }
                                                if let Some(redirect_url_str) = auth_json.redirect_url.as_deref() {
                                                    let redirect_url = match Url::from_str(redirect_url_str) {
                                                        Ok(url) => url,
                                                        Err(_) => {
                                                            eprintln!("Invalid redirect url :: {:?}", auth_json.redirect_url);
                                                            return std::ptr::null_mut()
                                                        }
                                                    };

                                                    if verbose_flag{
                                                        println!("Redirect url :: {}", redirect_url);
                                                    }
    
                                                    let redirect_params: HashMap<String, String> = form_urlencoded::parse(
                                                                                                                redirect_url
                                                                                                                .query()
                                                                                                                .unwrap_or("")
                                                                                                                .as_bytes()
                                                                                                            )
                                                                                                            .map(|(k, v)| (k.into_owned(), v.into_owned()))
                                                                                                            .collect();
                                                    
                                                    if let Some(code) = redirect_params.get("code") {
                                                        if verbose_flag{
                                                            println!("Code :: {}", code);
                                                        }

                                                        let api_secret_string: String = encode_item(
                                                                                                &format!(
                                                                                                    "{}{}{}", 
                                                                                                    api_key_str.clone(), 
                                                                                                    code.clone(), 
                                                                                                    api_secret_str
                                                                                                )
                                                                                            );
                                                        let token_payload: AuthTokenJson = AuthTokenJson {
                                                                                                    api_key: api_key_str,
                                                                                                    request_code: code.to_string(), 
                                                                                                    api_secret: api_secret_string
                                                                                                    };
                                                        match ROUTES.get("apitoken") {
                                                            Some(token_url) => {
                                                                match client.post(token_url)
                                                                            .json(&token_payload)
                                                                            .send()
                                                                            {
                                                                                Ok(response) => {
                                                                                    let token_json: TokenResponse = match response.json() {
                                                                                        Ok(json) => json,
                                                                                        Err(err) => {
                                                                                            eprintln!("Error in token json :: {}", err);
                                                                                            return std::ptr::null_mut();
                                                                                        }

                                                                                    };

                                                                                    if verbose_flag{
                                                                                        println!("Token Response :: {:?}", &token_json);
                                                                                    }

                                                                                    if let Some(token) = token_json.token.as_ref() {
                                                                                        if verbose_flag{
                                                                                            println!("Token :: {}", token);
                                                                                        }

                                                                                        let c_str = CString::new(token.to_string()).unwrap();
                                                                                        c_str.into_raw()
                                                                                    } else {
                                                                                        eprintln!("No token found isn response");
                                                                                        std::ptr::null_mut()
                                                                                    }
                                                                                } 
                                                                                Err(err) => {
                                                                                    eprintln!("Error in token request :: {}", err);
                                                                                    return std::ptr::null_mut();
                                                                                }
                                                                            }
                                                            }
                                                            None => {
                                                                eprintln!("api token url not found.");
                                                                return std::ptr::null_mut();
                                                            }
                                                        }
                                                    } else {
                                                        eprintln!("Code not found in response :: {:?}", redirect_params);
                                                        return std::ptr::null_mut();
                                                    }
    
                                                } else {
                                                    eprintln!("redirect url is not found in auth response.");
                                                    return std::ptr::null_mut();
                                                }
                                                } else {
                                                    println!("emsg not found in response..");
                                                    return std::ptr::null_mut();
                                            }                                            
                                                   
                                        }
                                        Err(err) => {
                                            eprintln!("Error in auth response : {}", err);
                                            return std::ptr::null_mut();
                                        }
                                    }
                                }
                                None => {
                                    eprintln!("Auth url not found.");
                                    return std::ptr::null_mut();
                                }
                            }

                        }
                        Err(err) => {
                            eprintln!("Error in fetching session : {}", err);
                            return std::ptr::null_mut();
                        }
                    }
                }
                None => {
                    eprintln!("Session url not found.");
                    return std::ptr::null_mut();
                }
            }

        } else {
            eprintln!("Error building client.");
            return std::ptr::null_mut();
    }

}