# aws-wire-lengths (`awl`)

A basic command-line interface for AWS that a human might actually want to use.
Now with online help!

```
$ aws-wire-lengths
Usage: aws-wire-lengths [OPTS] COMMAND [ARGS...]

Commands:
    instance (inst)     instance management
    volume (vol)        volume management
    snapshot (snap)     snapshot management
    image (ami)         image (AMI) management
    role                security token service (STS) management
    sg                  security group management
    key                 SSH key management
    vpc                 VPC management
    subnet              subnet management
    gateway (igw)       Internet gateway management
    nat                 managed NAT gateway management
    route (rt)          routing table management
    ip                  elastic IP address management
    interface (if)      network interface management
    config              manage account- or region-level configuration
    type                instance type management
    az                  availability zone management
    s3 (s)              S3 object storage


Options:
        --help          usage information
    -e                  use environment variables for credentials
    -r, --region-ec2 REGION
                        region for EC2
    -R, --region-s3 REGION
                        region for S3
        --region-sts REGION
                        region for STS

ERROR: choose a command
```

```
$ aws-wire-lengths inst
Usage: aws-wire-lengths instance COMMAND [ARGS...]

Commands:
    list (ls)           list instances
    ip                  get IP address for instance
    start               start an instance
    reboot              reboot an instance
    stop                stop an instance
    protect             enable termination protection
    unprotect           disable termination protection
    spoof               disable source/destination check
    nospoof             enable source/destination check
    create              create an instance
    destroy             destroy an instance
    diag (nmi)          send diagnostic interrupt to instance
    console             connect to the serial console of a guest
    volumes             show volumes attached to this instance


Options:
    --help              usage information

ERROR: choose a command
```
