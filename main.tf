terraform {
	required_providers {
		aws = {
			source = "hashicorp/aws"
			version = "~> 3.27"
		}
	}

	required_version = ">= 0.14.9"
}


provider "aws" {
	profile = "default"
	region = "eu-north-1"
}


resource "aws_vpc" "ecs-container-vpc" {
	cidr_block = "10.0.0.0/16"
    enable_dns_support = true
    enable_dns_hostnames = true


	tags = {
		Name = "ecs-container-vpc"
	}
}

resource "aws_internet_gateway" "ecs-container-gw" {
  vpc_id = aws_vpc.ecs-container-vpc.id

  tags = {
	Name = "ecs-container-gw"
  }
}

resource "aws_subnet" "ecs-container-subnet-1" {
	vpc_id     = aws_vpc.ecs-container-vpc.id
	cidr_block = "10.0.1.0/24"
	availability_zone = "eu-north-1a"

	tags = {
		Name = "ecs-container-subnet-1"
	}
}

resource "aws_subnet" "ecs-container-subnet-2" {
	vpc_id     = aws_vpc.ecs-container-vpc.id
	cidr_block = "10.0.2.0/24"
	availability_zone = "eu-north-1a"

	tags = {
		Name = "ecs-container-subnet-2"
	}
}

resource "aws_subnet" "ecs-container-subnet-3" {
	vpc_id     = aws_vpc.ecs-container-vpc.id
	cidr_block = "10.0.20.0/24"
	availability_zone = "eu-north-1b"

	tags = {
		Name = "ecs-container-subnet-3"
	}
}

resource "aws_subnet" "ecs-container-subnet-4" {
	vpc_id     = aws_vpc.ecs-container-vpc.id
	cidr_block = "10.0.21.0/24"
	availability_zone = "eu-north-1b"

	tags = {
		Name = "ecs-container-subnet-4"
	}
}


resource "aws_route_table" "ecs-container-route-table" {
	vpc_id = aws_vpc.ecs-container-vpc.id

	route {
		cidr_block = "0.0.0.0/0"
		gateway_id = aws_internet_gateway.ecs-container-gw.id
	}

	route {
		ipv6_cidr_block        = "::/0"
		gateway_id = aws_internet_gateway.ecs-container-gw.id
	}

	tags = {
		Name = "ecs-container-route-table"
	}
}

resource "aws_route_table" "ecs-container-route-table-private" {
	vpc_id = aws_vpc.ecs-container-vpc.id

	tags = {
		Name = "ecs-container-route-table-private"
	}
}

resource "aws_route_table_association" "ecs-container-route-association" {

	for_each		= toset([aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-3.id])  

	subnet_id		= each.key
	route_table_id	= aws_route_table.ecs-container-route-table.id
}

resource "aws_route_table_association" "ecs-container-route-association-private" {

	for_each		= toset([aws_subnet.ecs-container-subnet-2.id, aws_subnet.ecs-container-subnet-4.id])  

	subnet_id		= each.key
	route_table_id	= aws_route_table.ecs-container-route-table-private.id
}


resource "aws_vpc_endpoint" "s3-api" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.s3"
	tags = {
		Name = "s3-api"
	}

}

resource "aws_vpc_endpoint_route_table_association" "ecr-s3" {
  route_table_id  = aws_route_table.ecs-container-route-table.id
  vpc_endpoint_id = aws_vpc_endpoint.s3-api.id
}


resource "aws_vpc_endpoint_route_table_association" "ecr-s3-private" {
  route_table_id  = aws_route_table.ecs-container-route-table-private.id
  vpc_endpoint_id = aws_vpc_endpoint.s3-api.id
}



resource "aws_vpc_endpoint" "ecr-api" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.ecr.api"
    vpc_endpoint_type = "Interface"
    private_dns_enabled = true
    subnet_ids        = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-4.id]
    security_group_ids = [
        aws_security_group.private.id, aws_security_group.allow-web.id
    ]
	tags = {
		Name = "ecr-api"
	}

}

resource "aws_vpc_endpoint" "ecr-dkr" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.ecr.dkr"
    vpc_endpoint_type = "Interface"
    private_dns_enabled = true
    subnet_ids        = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-4.id]
    security_group_ids = [
        aws_security_group.private.id, aws_security_group.allow-web.id
    ]
	tags = {
		Name = "dkr-api"
	}

}

resource "aws_vpc_endpoint" "logs" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.logs"
    vpc_endpoint_type = "Interface"
    private_dns_enabled = true
    subnet_ids        = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-4.id]
    security_group_ids = [
        aws_security_group.private.id, aws_security_group.allow-web.id
    ]
	tags = {
		Name = "logs"
	}

}

resource "aws_vpc_endpoint" "ssm" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.ssm"
    vpc_endpoint_type = "Interface"
    private_dns_enabled = true
    subnet_ids        = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-4.id]
    security_group_ids = [
        aws_security_group.private.id, aws_security_group.allow-web.id
    ]
	tags = {
		Name = "ssm"
	}

}

resource "aws_vpc_endpoint" "secretsmanager" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.secretsmanager"
    vpc_endpoint_type = "Interface"
    private_dns_enabled = true
    subnet_ids        = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-4.id]
    security_group_ids = [
        aws_security_group.private.id, aws_security_group.allow-web.id
    ]
	tags = {
		Name = "secretsmanager"
	}

}

resource "aws_vpc_endpoint" "sqs" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.sqs"
    vpc_endpoint_type = "Interface"
    private_dns_enabled = true
    subnet_ids        = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-4.id]
    security_group_ids = [
        aws_security_group.private.id, aws_security_group.allow-web.id
    ]
	tags = {
		Name = "sqs"
	}

}

resource "aws_vpc_endpoint" "ses" {
    vpc_id       = aws_vpc.ecs-container-vpc.id
    service_name = "com.amazonaws.<region-name>.email-smtp"
    vpc_endpoint_type = "Interface"
    private_dns_enabled = true
    subnet_ids        = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-4.id]
    security_group_ids = [
        aws_security_group.private.id, aws_security_group.allow-web.id
    ]
	tags = {
		Name = "ses"
	}

}




resource "aws_security_group" "private" {
	name        = "private_traffic"
	description = "Limited private traffic"
	vpc_id      = aws_vpc.ecs-container-vpc.id

	ingress {
		description      = "Self"
		from_port        = 0
		to_port          = 0
        protocol         = "-1"
		self             = true
	}

	ingress {
		description     = "HTTP"
		from_port       = 80
		to_port         = 80
		protocol        = "all"
		security_groups = [aws_security_group.load-balancer-web.id]
	}

    egress {
        from_port        = 0
        to_port          = 0
        protocol         = "-1"
        cidr_blocks      = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
    }

	tags = {
		Name = "private-network"
	}
}

resource "aws_security_group" "allow-web" {
	name        = "allow_web_traffic"
	description = "Allow Web inbound traffic"
	vpc_id      = aws_vpc.ecs-container-vpc.id

	ingress {
		description      = "Self"
		from_port        = 0
		to_port          = 0
        protocol         = "-1"
		self             = true
	}

	ingress {
		description      = "HTTP"
		from_port        = 80
		to_port          = 80
		protocol         = "tcp"
		cidr_blocks      = ["0.0.0.0/0"]
	}

	ingress {
		description     = "HTTP"
		from_port       = 80
		to_port         = 80
		protocol        = "all"
		security_groups = [aws_security_group.load-balancer-web.id]
	}

    egress {
        from_port        = 0
        to_port          = 0
        protocol         = "-1"
        cidr_blocks      = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
    }

	tags = {
		Name = "allow-web"
	}
}

resource "aws_security_group" "load-balancer-web" {
	name        = "elbs-allow_web_traffic"
	description = "Allow Web inbound traffic"
	vpc_id      = aws_vpc.ecs-container-vpc.id

	ingress {
		description      = "HTTP"
		from_port        = 80
		to_port          = 80
		protocol         = "tcp"
		cidr_blocks      = ["0.0.0.0/0"]
	}

    egress {
        from_port        = 0
        to_port          = 0
        protocol         = "-1"
        cidr_blocks      = ["0.0.0.0/0"]
        ipv6_cidr_blocks = ["::/0"]
    }

	tags = {
		Name = "load-balancer-web"
	}
}


resource "aws_lb" "ecs-container-load-balancer" {
	name               = "ecs-container-load-balancer"
	internal           = false
	load_balancer_type = "application"
	security_groups    = [aws_security_group.load-balancer-web.id]
	subnets            = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-3.id]

	enable_deletion_protection = true
  	tags = {
    	Environment = "development"
  }
}

resource "aws_lb_target_group" "alb-target-group" {
	name        = "alb-target-group"
	port        = 80
	protocol    = "HTTP"
	target_type = "ip"
	vpc_id      = aws_vpc.ecs-container-vpc.id
    health_check {
        path = "/api"
    }

	depends_on = [aws_lb.ecs-container-load-balancer]
}

resource "aws_lb_listener" "http" {
	load_balancer_arn = aws_lb.ecs-container-load-balancer.arn
	port              = "80"
	protocol          = "HTTP"

	default_action {
		type             = "forward"
		target_group_arn = aws_lb_target_group.alb-target-group.arn

	}
}


# Create sqs
resource "aws_sqs_queue" "email-queue" {
    name                      = "email-queue"
    delay_seconds             = 90
    max_message_size          = 2048
    message_retention_seconds = 86400
    receive_wait_time_seconds = 10


    tags = {
        Environment = "development"
    }
}

resource "aws_iam_role" "ecs-flask-container-role" {
  name = "ecs-flask-container-role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
		{
			Action = "sts:AssumeRole"
			Effect = "Allow"
			Sid    = ""
			Principal = {
			Service = "ecs-tasks.amazonaws.com"
			}
		},
    ]
  })
   managed_policy_arns = [
                aws_iam_policy.sqs-policy.arn, 
                aws_iam_policy.ses-policy.arn, 
                aws_iam_policy.ecr-policy.arn, 
                aws_iam_policy.s3-policy.arn,
                aws_iam_policy.cloudwatch-policy.arn,
                aws_iam_policy.secrets-policy.arn,
            ]

  tags = {
    tag-key = "ecs-flask-container-role"
  }
}


resource "aws_iam_policy" "sqs-policy" {
  name = "sqs-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["sqs:*"]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "s3-policy" {
  name = "s3-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:*"]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "ses-policy" {
  name = "ses-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["ses:SendEmail", "ses:SendRawEmail"]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "ecr-policy" {
  name = "ecr-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
					"ecr:GetAuthorizationToken",
                	"ecr:BatchCheckLayerAvailability",
                	"ecr:GetDownloadUrlForLayer",
                	"ecr:BatchGetImage",
                	"logs:CreateLogStream",
                	"logs:PutLogEvents"
					]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "cloudwatch-policy" {
  name = "cloudwatch-policy"

    policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
            {
                Action = [
                    "autoscaling:Describe*",
                    "cloudwatch:*",
                    "logs:*",
                    "sns:*",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:GetRole"
                ],
                Effect = "Allow",
                Resource = "*"
            },
            {
                Effect = "Allow",
                Action = "iam:CreateServiceLinkedRole",
                Resource = "arn:aws:iam::*:role/aws-service-role/events.amazonaws.com/AWSServiceRoleForCloudWatchEvents*",
                Condition = {
                    StringLike = {
                        "iam:AWSServiceName": "events.amazonaws.com"
                    }
                }
            }
        ]
    })
}




resource "aws_iam_policy" "secrets-policy" {
  name = "secrets-policy"

    policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
        {
            Action = [
                "secretsmanager:*",
                "cloudformation:CreateChangeSet",
                "cloudformation:DescribeChangeSet",
                "cloudformation:DescribeStackResource",
                "cloudformation:DescribeStacks",
                "cloudformation:ExecuteChangeSet",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "kms:DescribeKey",
                "kms:ListAliases",
                "kms:ListKeys",
                "lambda:ListFunctions",
                "rds:DescribeDBClusters",
                "rds:DescribeDBInstances",
                "redshift:DescribeClusters",
                "tag:GetResources"
            ],
            Effect = "Allow",
            Resource = "*"
        },
        {
            Action = [
                "lambda:AddPermission",
                "lambda:CreateFunction",
                "lambda:GetFunction",
                "lambda:InvokeFunction",
                "lambda:UpdateFunctionConfiguration"
            ],
            Effect = "Allow",
            "Resource": "arn:aws:lambda:*:*:function:SecretsManager*"
        },
        {
            Action =  [
                "serverlessrepo:CreateCloudFormationChangeSet",
                "serverlessrepo:GetApplication"
            ],
            Effect = "Allow",
            Resource = "arn:aws:serverlessrepo:*:*:applications/SecretsManager*"
        },
        {
            Action = [
                "s3:GetObject"
            ],
            Effect = "Allow",
            Resource = [
                "arn:aws:s3:::awsserverlessrepo-changesets*",
                "arn:aws:s3:::secrets-manager-rotation-apps-*/*"
            ]
        }
    ]
})
}



# Create repository

resource "aws_ecr_repository" "flask-server" {
	name                 = "flask-server"
	image_tag_mutability = "MUTABLE"

	image_scanning_configuration {
		scan_on_push = true
	}
}

resource "aws_ecr_repository" "event-consumer" {
	name                 = "event-consumer"
	image_tag_mutability = "MUTABLE"

	image_scanning_configuration {
		scan_on_push = true
	}
}


# Create cluster

resource "aws_ecs_cluster" "flask-fargate-cluster" {
  name = "flask-fargate-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "task-definition-flask-server" {
	family = "ecs-container-task-definition"
	container_definitions = jsonencode([
		{
			name      = "flask-server"
			image     = "<account-id>.dkr.<region-name>.amazonaws.com/flask-server:latest"
			cpu       = 1024
			memory    = 2048
			essential = true
			portMappings = [
				{
				containerPort = 80
				hostPort      = 80
				}
			],
            logConfiguration = {
                logDriver = "awslogs",
                options = {
                    awslogs-group = "ecs",
                    awslogs-stream-prefix = "flask-server",
                    awslogs-region = "eu-north-1"
                }
            }
		}
  ])
    network_mode    = "awsvpc"
	cpu       = 1024
	memory    = 2048
    requires_compatibilities = ["FARGATE"]
    execution_role_arn = aws_iam_role.ecs-flask-container-role.arn
    task_role_arn  = aws_iam_role.ecs-flask-container-role.arn
}

resource "aws_ecs_task_definition" "task-definition-event-consumer" {
	family = "task-definition-event-consumer"
	container_definitions = jsonencode([
		{
			name      = "event-consumer"
			image     = "<account-id>.dkr.<region-name>.amazonaws.com/event-consumer:latest"
			cpu       = 1024
			memory    = 2048
			essential = true
			portMappings = [],
            logConfiguration = {
                logDriver = "awslogs",
                options = {
                    awslogs-group = "ecs",
                    awslogs-stream-prefix = "event-consumer",
                    awslogs-region = "eu-north-1"
                }
            }
		}
  ])
    network_mode    = "awsvpc"
	cpu       = 1024
	memory    = 2048
    requires_compatibilities = ["FARGATE"]
    execution_role_arn = aws_iam_role.ecs-flask-container-role.arn
    task_role_arn  = aws_iam_role.ecs-flask-container-role.arn
}

resource "aws_ecs_service" "flask-server" {
	name            = "flask-server"
	cluster         = aws_ecs_cluster.flask-fargate-cluster.id
	task_definition = aws_ecs_task_definition.task-definition-flask-server.arn
	launch_type     = "FARGATE"
	desired_count   = 2

	load_balancer {
		target_group_arn = aws_lb_target_group.alb-target-group.arn
		container_name   = "flask-server"
		container_port   = 80
	}

	network_configuration {
		subnets            = [aws_subnet.ecs-container-subnet-1.id, aws_subnet.ecs-container-subnet-3.id]
		security_groups    = [aws_security_group.allow-web.id]
		assign_public_ip = true
	}
}

resource "aws_ecs_service" "event-consumer" {
	name            = "event-consumer"
	cluster         = aws_ecs_cluster.flask-fargate-cluster.id
	task_definition = aws_ecs_task_definition.task-definition-event-consumer.arn
	launch_type     = "FARGATE"
	desired_count   = 2

	network_configuration {
		subnets            = [aws_subnet.ecs-container-subnet-2.id, aws_subnet.ecs-container-subnet-4.id]
        security_groups    = [aws_security_group.private.id]
	}
}

resource "aws_cloudwatch_log_group" "ecs" {
  name = "ecs"

  tags = {
    Environment = "development"
  }
}

resource "aws_cloudwatch_log_stream" "flask-server" {
  name           = "flask-server"
  log_group_name = aws_cloudwatch_log_group.ecs.name
}

resource "aws_cloudwatch_log_stream" "event-consumer" {
  name           = "event-consumer"
  log_group_name = aws_cloudwatch_log_group.ecs.name
}