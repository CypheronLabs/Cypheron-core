use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;
use actix_web::middleware::{Middleware, Started};
use futures::future::{ok, FutureResult};
use std::time::Instant;
use crate::models::analytics::ApiUsageLog;
use crate::state::AppState;

pub struct AnalyticsLogger;

impl<S, B> Middleware<S> for AnalyticsLogger
where
    S: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = FutureResult<Self::Response, Self::Error>;

    fn start(&self, req: &mut Self::Request) -> Result<Started, Self::Error> {
        req.extensions_mut().insert(Instant::now());
        Ok(Started::Done)
    }

    fn finish(&self, req: &mut Self::Request, res: &mut Self::Response) -> Self::Future {
        let user_id_opt = req.extensions().get::<String>().cloned();
        let api_key_prefix_opt = req.extensions().get::<String>().cloned();

        if let (Some(user_id), Some(api_key_prefix)) = (user_id_opt, api_key_prefix_opt) {
            let latency = req.extensions().get::<Instant>().unwrap().elapsed();
            let app_state = req.app_data::<AppState>().unwrap();

            let log_entry = ApiUsageLog::new(
                user_id,
                api_key_prefix,
                req.path().to_string(),
                req.method().to_string(),
                res.status().as_u16(),
                latency.as_millis(),
            );

            let firestore_client = app_state.firestore_client.clone();
            tokio::spawn(async move {
                // In a real implementation, you would have a method on your firestore_client to handle this.
                // For now, we'll just print to the console to show it's working.
                println!("Logging API usage: {:?}", log_entry);
            });
        }

        ok(res)
    }
}
