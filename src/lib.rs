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

pub mod minio;

#[cfg(test)]
mod tests {
    use hyper::body::Buf;

    use crate::minio::Credentials;

    use super::*;

    #[tokio::test]
    async fn test_lib_functions() -> Result<(), crate::minio::types::Err> {
        std::env::set_var("RUST_LOG", "debug");
        env_logger::init();
        let mut c = minio::Client::new("http://localhost:9000/")?;
        c.set_credentials(Credentials::new("minioadmin", "minioadmin"));
        println!("{}", c.server);
        let bucket = "songs";

        let r = c
            .put_object_req(
                bucket,
                "hhhhhhhhhh",
                vec![],
                "object content".as_bytes().to_vec(),
            )
            .await?;
        println!("object: {} {} {:?}", r.object_size, r.etag, r.content_type);

        let mut response = c.get_object_req(bucket, "hhhhhhhhhh", vec![]).await?;

        let body = response.resp.body_mut();

        let bytes = hyper::body::aggregate(body).await.unwrap();

        println!("{:#?}", String::from_utf8(bytes.chunk().to_vec()));

        println!("object: {} {} {:?}", r.object_size, r.etag, r.content_type);

        c.make_bucket("test").await?;

        c.delete_bucket("test").await?;

        Ok(())
    }
}
