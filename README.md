# aws-wire-lengths (`awl`)

A basic command-line interface for AWS that a human might actually want to use.
Now with online help!

```
$ aws-wire-lengths
Usage: aws-wire-lengths COMMAND [OPTS] [ARGS...]

Commands:
    instance (inst)     instance management
    volume (vol)        volume management
    snapshot (snap)     snapshot management
    image (ami)         image (AMI) management


Options:
        --help          usage information
    -e                  use environment variables for credentials
    -r, --region-ec2 REGION
                        region for EC2
    -R, --region-s3 REGION
                        region for S3

ERROR: choose a command
```

```
$ aws-wire-lengths inst
Usage: aws-wire-lengths instance COMMAND [OPTS] [ARGS...]

Commands:
    list (ls)           list instances
    ip                  get IP address for instance
    start               start an instance
    stop                stop an instance
    protect             enable termination protection
    unprotect           disable termination protection
    create              create an instance
    destroy             destroy an instance


Options:
    --help              usage information

ERROR: choose a command
```
