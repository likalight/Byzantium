use reqwest::Client;
use crate::error::BillingError;

pub struct StripeClient {
    client: Client,
    secret_key: String,
    base_url: String,
}

impl StripeClient {
    pub fn new(secret_key: String) -> Self {
        Self {
            client: Client::new(),
            secret_key,
            base_url: "https://api.stripe.com/v1".to_string(),
        }
    }

    pub fn from_env() -> Option<Self> {
        std::env::var("STRIPE_SECRET_KEY").ok().map(Self::new)
    }

    async fn post_form(&self, path: &str, params: Vec<(&str, String)>) -> Result<serde_json::Value, BillingError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.client
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .form(&params)
            .send()
            .await?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await?;
        if !status.is_success() {
            return Err(BillingError::Stripe(
                body["error"]["message"].as_str().unwrap_or("unknown").to_string()
            ));
        }
        Ok(body)
    }

    pub async fn report_usage(
        &self,
        subscription_item_id: &str,
        quantity: u64,
        timestamp: i64,
    ) -> Result<(), BillingError> {
        self.post_form(
            &format!("/subscription_items/{}/usage_records", subscription_item_id),
            vec![
                ("quantity", quantity.to_string()),
                ("timestamp", timestamp.to_string()),
                ("action", "increment".to_string()),
            ],
        ).await?;
        Ok(())
    }

    pub async fn create_customer(&self, email: &str, name: &str) -> Result<String, BillingError> {
        let body = self.post_form("/customers", vec![
            ("email", email.to_string()),
            ("name", name.to_string()),
        ]).await?;
        body["id"].as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| BillingError::Stripe("no id in customer response".into()))
    }

    pub async fn create_usage_subscription(
        &self,
        customer_id: &str,
        price_id: &str,
    ) -> Result<String, BillingError> {
        let body = self.post_form("/subscriptions", vec![
            ("customer", customer_id.to_string()),
            ("items[0][price]", price_id.to_string()),
        ]).await?;
        body["id"].as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| BillingError::Stripe("no id in subscription response".into()))
    }
}
