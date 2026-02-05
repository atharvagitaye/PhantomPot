pipeline {
    agent any

    stages {
        stage('Setup Python') {
            steps {
                bat 'python -m venv venv'
                bat 'venv\\Scripts\\pip install -r requirements.txt'
            }
        }

        stage('Lint') {
            steps {
                // Ignore errors so the pipeline continues to tests
                bat 'venv\\Scripts\\flake8 . --exclude=venv || exit 0'
            }
        }

        stage('Test') {
            steps {
                // Ensure pytest is installed and then run it
                bat 'venv\\Scripts\\pip install pytest'
                bat 'venv\\Scripts\\pytest'
            }
        }
    }

    post {
        always {
            echo 'Build process completed.'
        }
        success {
            echo '✅ Build Passed!'
        }
        failure {
            echo '❌ Build Failed!'
        }
    }
} // Line 45: Ensure this is the ONLY closing brace at the very end
