- Create a github action to use the runner and create the infrastructure to run the tests
    - Create a new file in the `.github/workflows` folder called `test.yml`
    - Workflow Pseudocode:
        ```yaml
        name: Test Infra
        runner: cloud-runner here
        jobs:
            create-runner:
            start-runner:
            install-dependencies:
            get-rancher-config:
            install-rancher-in-specified-config:
            test:
                runs-on: runner
                steps:
                    - name: Checkout code
                      uses: actions/checkout@v2
                    - name: Install dependencies
                      run: npm install
                    - name: Run tests
                      run: npm test
            update-qase:
            stop-runner:
            get-logs:
            save-artifacts:
            destroy-runner:
        ```