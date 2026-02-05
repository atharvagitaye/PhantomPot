pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                // Jenkins usually handles the SCM checkout automatically, 
                // but if you have a manual checkout stage:
                checkout scm
            }
        }

        stage('Setup Python') {
            steps {
                // Using 'bat' instead of 'sh' for Windows
                bat 'python --version'
                bat 'python -m venv venv'
                bat 'venv\\Scripts\\pip install -r requirements.txt'
            }
        }

        stage('Lint') {
            steps {
                // The --exclude flag tells flake8 to ignore the venv folder
                bat 'venv\\Scripts\\flake8 . --exclude=venv'
            }
        }

        stage('Test') {
            steps {
                bat 'venv\\Scripts\\pytest'
            }
        }
    }

    post {
        always {
            // Changed from sh to echo or bat to prevent the post-action crash
            echo 'Build process completed.'
        }
        failure {
            echo '❌ Build failed!'
        }
    }
}
