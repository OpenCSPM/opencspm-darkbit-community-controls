# OpenCSPM Community Control Pack

## Description

This repository contains the public/community controls, supporting metadata, and check logic for use with [OpenCSPM](https://github.com/opencspm/opencspm).  Security checks that cover the [AWS CIS 1.3.0](https://www.cisecurity.org/benchmark/amazon_web_services/), [AWS EKS 1.0.1](https://www.cisecurity.org/benchmark/kubernetes/), [GCP CIS 1.1](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/), and [GKE CIS 1.1](https://www.cisecurity.org/benchmark/kubernetes/) Benchmarks are largely the scope of this control pack, but that is subject to change.

For more complete and in-depth security coverage, please refer to the [OpenCSPM Enterprise Control Pack](https://github.com/opencspm/opencspm-darkbit-enterprise-controls).

## Requirements

This repository is meant to be used in conjunction with an installation of the [OpenCSPM](https://github.com/opencspm/opencspm) solution.

## What is OpenCSPM?

Open Cloud Security Posture Management, [OpenCSPM](https://github.com/opencspm/opencspm), is an open-source platform for gaining deeper insight into your cloud configuration and metadata to help understand and reduce risk over time.

## Development

Create a Gemset.

```
rvm use 2.6.6@opencspm-controls --create --ruby-version
```

For VS Code Ruby Language Server support, install `solargraph` and `rubocop`.

```
bundle install
```

## Authorship

This repository was developed and is maintained by [Darkbit, LLC](https://darkbit.io)
