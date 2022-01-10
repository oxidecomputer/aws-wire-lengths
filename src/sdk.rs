use anyhow::{anyhow, Result};
use aws_sdk_ec2 as ec2;
use aws_types::region::Region;

pub struct More {
    region_ec2: Region,
    ec2: Option<ec2::Client>,
}

impl More {
    pub async fn new(region_ec2: Option<&str>) -> Result<More> {
        let rp = aws_config::meta::region::RegionProviderChain::first_try(
            region_ec2.map(|s| Region::new(s.to_string())),
        )
        .or_default_provider()
        .or_else(Region::new("us-east-1"));

        let r = rp.region().await
            .ok_or_else(|| anyhow!("could not get region for EC2"))?;

        let mut m = More {
            region_ec2: r,
            ec2: None,
        };

        let cfg = aws_config::from_env().load().await;

        m.ec2 = Some(ec2::Client::new(&cfg));

        Ok(m)
    }

    pub fn ec2(&self) -> &ec2::Client {
        self.ec2.as_ref().unwrap()
    }
}
