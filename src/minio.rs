/*
 * MinIO Rust Library for Amazon S3 Compatible Cloud Storage
 * Copyright 2019 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use hyper::body::Buf;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{body::Body, client, header, header::HeaderMap, Method, Response, Uri};
use hyper_tls::HttpsConnector;
use log::{debug, trace};
use std::env;
use std::str;
use std::string::String;
use time;
use time::Tm;
use serde_derive::Serialize;

pub use hyper::http::StatusCode;

pub use types::BucketInfo;
use types::{Err, GetObjectResp, ListObjectsResp, Region};

use crate::minio::net::{Values, ValuesAccess};

mod api;
mod api_notification;
mod net;
mod sign;
pub mod types;
mod woxml;
mod xml;
mod crypt;
use crypt::*;

pub const SPACE_BYTE: &[u8; 1] = b" ";

#[derive(Debug, Clone)]
pub struct Credentials {
    access_key: String,
    secret_key: String,
}

impl Credentials {
    pub fn new(ak: &str, sk: &str) -> Credentials {
        Credentials {
            access_key: ak.to_string(),
            secret_key: sk.to_string(),
        }
    }

    pub fn from_env() -> Result<Credentials, Err> {
        let (ak, sk) = (env::var("MINIO_ACCESS_KEY"), env::var("MINIO_SECRET_KEY"));
        match (ak, sk) {
            (Ok(ak), Ok(sk)) => Ok(Credentials::new(ak.as_str(), sk.as_str())),
            _ => Err(Err::InvalidEnv(
                "Missing MINIO_ACCESS_KEY or MINIO_SECRET_KEY environment variables".to_string(),
            )),
        }
    }
}

#[derive(Clone)]
enum ConnClient {
    HttpCC(hyper::client::Client<client::HttpConnector, Body>),
    HttpsCC(client::Client<HttpsConnector<client::HttpConnector>, Body>),
}

impl ConnClient {
    fn make_req(&self, req: hyper::http::Request<Body>) -> client::ResponseFuture {
        match self {
            ConnClient::HttpCC(c) => c.request(req),
            ConnClient::HttpsCC(c) => c.request(req),
        }
    }
}

#[derive(Clone)]
pub struct Client {
    pub server: Uri,
    region: Region,
    conn_client: ConnClient,
    pub credentials: Option<Credentials>,
}

impl Client {
    /// Creates new client
    pub fn new(server: &str) -> Result<Client, Err> {
        let valid = server.parse::<Uri>();
        match valid {
            Ok(server_uri) => {
                if server_uri.host().is_none() {
                    Err(Err::InvalidUrl("no host specified!".to_string()))
                } else if server_uri.scheme_str() != Some("http")
                    && server_uri.scheme_str() != Some("https")
                {
                    Err(Err::InvalidUrl("invalid scheme!".to_string()))
                } else {
                    Ok(Client {
                        server: server_uri.clone(),
                        region: Region::empty(),
                        conn_client: if server_uri.scheme_str() == Some("http") {
                            ConnClient::HttpCC(client::Client::new())
                        } else {
                            let https = HttpsConnector::new();
                            ConnClient::HttpsCC(
                                client::Client::builder().build::<_, hyper::Body>(https),
                            )
                        },
                        credentials: None,
                    })
                }
            }
            Err(err) => Err(Err::InvalidUrl(err.to_string())),
        }
    }

    /// Sets client credentials
    pub fn set_credentials(&mut self, credentials: Credentials) {
        self.credentials = Some(credentials);
    }

    /// Sets region of S3 service
    pub fn set_region(&mut self, r: Region) {
        self.region = r;
    }

    /// Converts a `hyper::Chunk` into a string.
    pub async fn chunk_to_string(&self, chunk: &mut hyper::Body) -> Result<String, Err> {
        match hyper::body::aggregate(chunk).await {
            Ok(s) => match String::from_utf8(s.chunk().to_vec()) {
                Err(e) => Err(Err::Utf8DecodingErr(e)),
                Ok(s) => Ok(s.to_string()),
            },
            Err(err) => Err(Err::HyperErr(err)),
        }
    }

    /// Converts a `hyper::Chunk` into a vector of bytes.
    pub async fn chunk_to_bytes(&self, chunk: &mut hyper::Body) -> Result<Vec<u8>, Err> {
        match hyper::body::aggregate(chunk).await {
            Ok(s) => Ok(s.chunk().to_vec()),
            Err(err) => Err(Err::HyperErr(err)),
        }
    }

    /// Converts a `hyper::Response` into a string
    pub async fn parse_response(&self, resp:hyper::Response<Body>) -> Result<String, Err> {
        let mut body = resp.into_body();
        let s = self.chunk_to_string(&mut body).await?;
        Ok(s)
    }

    /// Adds host header to the provided `HeaderMap`
    fn add_host_header(&self, header_map: &mut HeaderMap) {
        let host_val = match self.server.port() {
            Some(port) => format!("{}:{}", self.server.host().unwrap_or(""), port),
            None => self.server.host().unwrap_or("").to_string(),
        };
        match header::HeaderValue::from_str(&host_val) {
            Ok(v) => {
                header_map.insert(header::HOST, v);
            }
            _ => {}
        }
    }

    /// Creates client and connects to public play service
    pub fn get_play_client() -> Client {
        Client {
            server: "https://play.min.io:9000".parse::<Uri>().unwrap(),
            region: Region::new("us-east-1"),
            conn_client: {
                let https = HttpsConnector::new();
                ConnClient::HttpsCC(client::Client::builder().build::<_, hyper::Body>(https))
            },
            credentials: Some(Credentials::new(
                "Q3AM3UQ867SPQQA43P2F",
                "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
            )),
        }
    }

    /// Core request creation
    async fn signed_req_future(
        &self,
        mut s3_req: S3Req,
        body_res: Result<Body, Err>,
    ) -> Result<Response<Body>, types::Err> {
        let hmap = &mut s3_req.headers;
        self.add_host_header(hmap);

        let body_hash_hdr = (
            HeaderName::from_static("x-amz-content-sha256"),
            HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
        hmap.insert(body_hash_hdr.0.clone(), body_hash_hdr.1.clone());
        let creds = self.credentials.clone();
        let region = self.region.clone();
        let server_addr = self.server.to_string();
        let conn_client = self.conn_client.clone();

        match body_res {
            Ok(body) => {
                s3_req.body = body;
                let sign_hdrs = sign::sign_v4(&s3_req, creds, region);
                debug!("signout: {:?}", sign_hdrs);
                match api::mk_request(s3_req, &server_addr, &sign_hdrs) {
                    Ok(req) => {
                        trace!("{:?}", req);
                        match conn_client.make_req(req).await {
                            Ok(resp) => {
                                let st = resp.status();
                                if st.is_success() {
                                    return Ok(resp);
                                } else {
                                    return Err(Err::RawSvcErr(st, resp));
                                }
                            }
                            Err(err) => Err(types::Err::HyperErr(err)),
                        }
                    }
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// GET request abstraction
    pub async fn get_object_req(
        &self,
        bucket_name: &str,
        key: &str,
        get_obj_opts: Vec<(HeaderName, HeaderValue)>,
    ) -> Result<GetObjectResp, Err> {
        let mut h = HeaderMap::new();
        get_obj_opts
            .iter()
            .map(|(x, y)| (x.clone(), y.clone()))
            .for_each(|(k, v)| {
                h.insert(k, v);
            });

        let s3_req = S3Req {
            method: Method::GET,
            bucket: Some(bucket_name.to_string()),
            object: Some(key.to_string()),
            headers: h,
            query: Values::new(),
            body: Body::empty(),
            ts: time::now_utc(),
        };

        let body = self.signed_req_future(s3_req, Ok(Body::empty())).await?;
        GetObjectResp::new(body)
    }

    /// PUT request abstraction
    pub async fn put_object_req(
        &self,
        bucket_name: &str,
        key: &str,
        get_obj_opts: Vec<(HeaderName, HeaderValue)>,
        data: Vec<u8>,
    ) -> Result<GetObjectResp, Err> {
        let mut h = HeaderMap::new();
        get_obj_opts
            .iter()
            .map(|(x, y)| (x.clone(), y.clone()))
            .for_each(|(k, v)| {
                h.insert(k, v);
            });

        let s3_req = S3Req {
            method: Method::PUT,
            bucket: Some(bucket_name.to_string()),
            object: Some(key.to_string()),
            headers: h,
            query: Values::new(),
            body: Body::from(data.clone()),
            ts: time::now_utc(),
        };

        let body = self.signed_req_future(s3_req, Ok(Body::from(data))).await?;
        GetObjectResp::new(body)
    }

    /// Get request abstraction for lists of objects with output handling
    pub async fn list_objects(
        &self,
        b: &str,
        prefix: Option<&str>,
        marker: Option<&str>,
        delimiter: Option<&str>,
        max_keys: Option<i32>,
    ) -> Result<ListObjectsResp, Err> {
        let mut qparams: Values = Values::new();
        qparams.set_value("list-type", Some("2".to_string()));
        if let Some(d) = delimiter {
            qparams.set_value("delimiter", Some(d.to_string()));
        }
        if let Some(m) = marker {
            qparams.set_value("marker", Some(m.to_string()));
        }

        if let Some(p) = prefix {
            qparams.set_value("prefix", Some(p.to_string()));
        }

        if let Some(mkeys) = max_keys {
            qparams.set_value("max-keys", Some(mkeys.to_string()));
        }

        let s3_req = S3Req {
            method: Method::GET,
            bucket: Some(b.to_string()),
            object: None,
            query: qparams,
            headers: HeaderMap::new(),
            body: Body::empty(),
            ts: time::now_utc(),
        };
        let resp = self.signed_req_future(s3_req, Ok(Body::empty())).await?;
        let s = self.parse_response(resp).await?;
        xml::parse_list_objects(s)
    }

    /// Gets location for the bucket_name.
    pub async fn get_bucket_location(&self, bucket_name: &str) -> Result<Region, Err> {
        let mut qp = Values::new();
        qp.set_value("location", None);

        let s3_req = S3Req {
            method: Method::GET,
            bucket: Some(bucket_name.to_string()),
            object: None,
            headers: HeaderMap::new(),
            query: qp,
            body: Body::empty(),
            ts: time::now_utc(),
        };
        match self.signed_req_future(s3_req, Ok(Body::empty())).await {
            Ok(resp) => {
                let s = self.parse_response(resp).await?;
                xml::parse_bucket_location(s)
            }
            Err(err) => Err(err),
        }
    }

    /// Deletes bucket
    pub async fn delete_bucket(&self, bucket_name: &str) -> Result<(), Err> {
        let s3_req = S3Req {
            method: Method::DELETE,
            bucket: Some(bucket_name.to_string()),
            object: None,
            headers: HeaderMap::new(),
            query: Values::new(),
            body: Body::empty(),
            ts: time::now_utc(),
        };
        self.signed_req_future(s3_req, Ok(Body::empty())).await?;
        Ok(())
    }

    /// Checks if bucket exists
    pub async fn bucket_exists(&self, bucket_name: &str) -> Result<bool, Err> {
        let s3_req = S3Req {
            method: Method::HEAD,
            bucket: Some(bucket_name.to_string()),
            object: None,
            headers: HeaderMap::new(),
            query: Values::new(),
            body: Body::empty(),
            ts: time::now_utc(),
        };
        let res = self.signed_req_future(s3_req, Ok(Body::empty())).await;
        match res {
            Ok(_) => Ok(true),
            Err(Err::FailStatusCodeErr(st, b)) => {
                let code = st.as_u16();
                if code == 404 {
                    Ok(false)
                } else {
                    Err(Err::FailStatusCodeErr(st, b))
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Creates bucket
    pub async fn make_bucket(&self, bucket_name: &str) -> Result<(), Err> {
        let xml_body_res = xml::get_mk_bucket_body();
        let bucket = bucket_name.clone().to_string();
        let s3_req = S3Req {
            method: Method::PUT,
            bucket: Some(bucket),
            object: None,
            query: Values::new(),
            headers: HeaderMap::new(),
            body: Body::empty(),
            ts: time::now_utc(),
        };
        self.signed_req_future(s3_req, xml_body_res).await?;
        Ok(())
    }

    /// Gets list of buckets
    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>, Err> {
        let s3_req = S3Req {
            method: Method::GET,
            bucket: None,
            object: None,
            query: Values::new(),
            headers: HeaderMap::new(),
            body: Body::empty(),
            ts: time::now_utc(),
        };
        let resp = self.signed_req_future(s3_req, Ok(Body::empty())).await?;
        let s = self.parse_response(resp).await?;
        xml::parse_bucket_list(s)
    }

    /// Creates user or set status
    pub async fn set_user(&self, creds: Credentials, enabled: bool) -> Result<Response<Body>, types::Err> {
        let bucket = "minio/admin/v3";
        let object = "add-user";
        let json   = format!("{{\"SecretKey\":\"{}\",\"Status\":\"{}\"}}", &creds.secret_key, if enabled {"enabled"}  else  {"disabled"});
        let passwd = match &self.credentials {
            Some(cred) => cred.secret_key.clone(),
            None => String::from("this arm should be unreachable")
        };
        let data = sio_encrypt(passwd, json.as_bytes().to_vec(), true).await.unwrap();
        let mut qparams: Values = Values::new();
        qparams.set_value("accessKey", Some(creds.access_key));

        let s3_req = S3Req {
            method: Method::PUT,
            bucket: Some(bucket.to_string()),
            object: Some(object.to_string()),
            headers: HeaderMap::new(),
            query: qparams,
            body: Body::from(data.clone()),
            ts: time::now_utc(),
        };
        self.signed_req_future(s3_req, Ok(Body::from(data.clone()))).await
    }

    /// Sets user status
    pub async fn set_user_status(&self, access_key: String, enabled: bool) -> Result<Response<Body>, types::Err> {
        let bucket = "minio/admin/v3";
        let object = "set-user-status";
        let mut qparams: Values = Values::new();
        qparams.set_value("accessKey", Some(access_key));
        qparams.set_value("status", if enabled {Some("enabled".to_owned())}  else  {Some("disabled".to_owned())});

        let s3_req = S3Req {
            method: Method::PUT,
            bucket: Some(bucket.to_string()),
            object: Some(object.to_string()),
            headers: HeaderMap::new(),
            query: qparams,
            body: Body::empty(),
            ts: time::now_utc(),
        };
        self.signed_req_future(s3_req, Ok(Body::empty())).await
    }

    /// Deletes user
    pub async fn remove_user(&self, access_key: String) -> Result<Response<Body>, types::Err> {
        let bucket = "minio/admin/v3";
        let object = "remove-user";
        let mut qparams: Values = Values::new();
        qparams.set_value("accessKey", Some(access_key));

        let s3_req = S3Req {
            method: Method::DELETE,
            bucket: Some(bucket.to_string()),
            object: Some(object.to_string()),
            headers: HeaderMap::new(),
            query: qparams,
            body: Body::empty(),
            ts: time::now_utc(),
        };
        self.signed_req_future(s3_req, Ok(Body::empty())).await
    }

    /// Gets user and status
    pub async fn get_user(&self, access_key: String) -> Result<String, types::Err> {
        let bucket = "minio/admin/v3";
        let object = "user-info";
        let mut qparams: Values = Values::new();
        qparams.set_value("accessKey", Some(access_key));

        let s3_req = S3Req {
            method: Method::GET,
            bucket: Some(bucket.to_string()),
            object: Some(object.to_string()),
            headers: HeaderMap::new(),
            query: qparams,
            body: Body::empty(),
            ts: time::now_utc(),
        };
        match self.signed_req_future(s3_req, Ok(Body::empty())).await {
            Ok(resp) => {
                self.parse_response(resp).await
            }
            Err(err) => Err(err),
        }
    }

    /// Gets user list
    pub async fn list_users(&self) -> Result<String, types::Err> {
        let bucket = "minio/admin/v3";
        let object = "list-users";
        let s3_req = S3Req {
            method: Method::GET,
            bucket: Some(bucket.to_string()),
            object: Some(object.to_string()),
            headers: HeaderMap::new(),
            query: Values::new(),
            body: Body::empty(),
            ts: time::now_utc(),
        };
        match self.signed_req_future(s3_req, Ok(Body::empty())).await {
            Ok(resp) => {
                let passwd = match &self.credentials {
                    Some(cred) => cred.secret_key.clone(),
                    None => String::from("this arm should be unreachable")
                };
                let mut body = resp.into_body();
                let ciphertext = self.chunk_to_bytes(&mut body).await?;
                let plaintext = sio_decrypt(passwd, ciphertext).await.unwrap();
                let user_list = String::from_utf8(plaintext).unwrap();
                Ok(user_list)
            },
            Err(e) => Err(e)
        }
    }

    /// Sets group parameters incuding membership and boolean flag to delete (if there are no members)
    pub async fn set_group(&self, params: GroupParams) -> Result<Response<Body>, types::Err> {
        let bucket = "minio/admin/v3";
        let object = "update-group-members";
        let data = serde_json::to_string(&params).unwrap();
        let s3_req = S3Req {
            method: Method::PUT,
            bucket: Some(bucket.to_string()),
            object: Some(object.to_string()),
            headers: HeaderMap::new(),
            query: Values::new(),
            body: Body::from(data.clone()),
            ts: time::now_utc(),
        };
        self.signed_req_future(s3_req, Ok(Body::from(data.clone()))).await
    }

    /// Convenience method to create user and return their state
    pub async fn make_user(&self, creds: Credentials) -> Result<String, types::Err> {
        let ak = String::from(&creds.access_key);
        match  self.set_user(creds, true).await {
            Ok(_) => self.get_user(ak).await,
            Err(e) => Err(e)
        }
    }
}

// async fn run_req_future(
//     req_result: Result<Request<Body>, Err>,
//     c: ConnClient,
// ) -> Result<Response<Body>, Err> {
//     match c.make_req(req_result?).await {
//         Ok(resp) => {
//             let st = resp.status();
//             if st.is_success() {
//                 Ok(resp)
//             } else {
//                 Err(Err::RawSvcErr(st, resp))
//             }
//         }
//         Err(err) => Err(Err::HyperErr(err)),
//     }
// }


#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupParams {
    pub group: String,
    pub members: Vec<String>,
    pub group_status: String,
    pub is_remove: bool
}

pub struct S3Req {
    method: Method,
    bucket: Option<String>,
    object: Option<String>,
    headers: HeaderMap,
    query: Values,
    body: Body,
    ts: Tm,
}

impl S3Req {
    fn mk_path(&self) -> String {
        let mut res: String = String::from("/");
        if let Some(s) = &self.bucket {
            res.push_str(&s);
            res.push_str("/");
            if let Some(o) = &self.object {
                res.push_str(&o);
            }
        };
        res
    }

    /// Takes the query_parameters and turn them into a valid query string for example:
    /// {"key1":["val1","val2"],"key2":["val1","val2"]}
    /// will be returned as:
    /// "key1=val1&key1=val2&key2=val3&key2=val4"
    fn mk_query(&self) -> String {
        self.query
            .iter()
            .map(|(key, values)| {
                values.iter().map(move |value| match value {
                    Some(v) => format!("{}={}", &key, v),
                    None => format!("{}=", &key,),
                })
            })
            .flatten()
            .collect::<Vec<String>>()
            .join("&")
    }
}

#[cfg(test)]
mod minio_tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn serialize_query_parameters() {
        let mut query_params: HashMap<String, Vec<Option<String>>> = HashMap::new();
        query_params.insert(
            "key1".to_string(),
            vec![Some("val1".to_string()), Some("val2".to_string())],
        );
        query_params.insert(
            "key2".to_string(),
            vec![Some("val3".to_string()), Some("val4".to_string())],
        );

        let s3_req = S3Req {
            method: Method::GET,
            bucket: None,
            object: None,
            headers: HeaderMap::new(),
            query: query_params,
            body: Body::empty(),
            ts: time::now_utc(),
        };
        let result = s3_req.mk_query();
        assert!(result.contains("key1=val1"));
        assert!(result.contains("key1=val2"));
        assert!(result.contains("key2=val3"));
        assert!(result.contains("key2=val4"));
    }
}
