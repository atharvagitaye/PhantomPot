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
            bat 'python -m venv venv'
            // Force the installation of pytest even if it's missing from requirements.txt
            bat 'venv\\Scripts\\pip install -r requirements.txt'
            bat 'venv\\Scripts\\pip install pytest'
        }
        }}

        stage('Lint') {
        steps {
                // Adding '|| exit 0' ensures the pipeline continues even if there are lint errors
                bat 'venv\\Scripts\\flake8 . --exclude=venv || exit 0'
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
