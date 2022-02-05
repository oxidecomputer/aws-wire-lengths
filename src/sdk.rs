use anyhow::{anyhow, Result};
use aws_sdk_ec2 as ec2;
use aws_sdk_s3 as s3;
use aws_types::region::Region;

pub struct More {
    region_ec2: Region,
    ec2: Option<ec2::Client>,
    region_s3: Region,
    s3: Option<s3::Client>,
}

impl More {
    pub async fn new(
        region_ec2: Option<&str>,
        region_s3: Option<&str>,
    ) -> Result<More> {
        let region_ec2 =
            aws_config::meta::region::RegionProviderChain::first_try(
                region_ec2.map(|s| Region::new(s.to_string())),
            )
            .or_default_provider()
            .or_else(Region::new("us-east-1"))
            .region()
            .await
            .ok_or_else(|| anyhow!("could not get region for EC2"))?;

        let region_s3 =
            aws_config::meta::region::RegionProviderChain::first_try(
                region_s3.map(|s| Region::new(s.to_string())),
            )
            .or_default_provider()
            .or_else(Region::new("us-east-1"))
            .region()
            .await
            .ok_or_else(|| anyhow!("could not get region for S3"))?;

        let mut m = More {
            region_ec2,
            region_s3,
            ec2: None,
            s3: None,
        };

        let cfg = aws_config::from_env()
            .region(m.region_ec2.clone())
            .load()
            .await;
        m.ec2 = Some(ec2::Client::new(&cfg));

        let cfg = aws_config::from_env()
            .region(m.region_s3.clone())
            .load()
            .await;
        m.s3 = Some(s3::Client::new(&cfg));

        Ok(m)
    }

    pub fn ec2(&self) -> &ec2::Client {
        self.ec2.as_ref().unwrap()
    }

    pub fn s3(&self) -> &s3::Client {
        self.s3.as_ref().unwrap()
    }

    pub fn region_s3(&self) -> &Region {
        &self.region_s3
    }
}
