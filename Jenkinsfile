pipeline {
    agent any

    environment {
        VENV = 'venv'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Setup Python') {
            steps {
                sh '''
                python3 --version
                python3 -m venv $VENV
                . $VENV/bin/activate
                pip install --upgrade pip
                pip install -r requirements.txt
                '''
            }
        }

        stage('Lint') {
            steps {
                sh '''
                . $VENV/bin/activate
                flake8 app || true
                '''
            }
        }

        stage('Test') {
            steps {
                sh '''
                . $VENV/bin/activate
                pytest -v
                '''
            }
        }
    }

    post {
        success {
            echo '✅ Build and tests passed!'
        }
        failure {
            echo '❌ Build failed!'
        }
        always {
            sh 'rm -rf venv'
        }
    }
}
