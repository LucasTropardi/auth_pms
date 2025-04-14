pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "auth-service"
        CONTAINER_NAME = "auth-service-container"
    }

    stages {
        stage('Clone') {
            steps {
                git credentialsId: 'github', url: 'https://github.com/LucasTropardi/auth_pms.git'
            }
        }

        stage('Build Maven') {
            steps {
                sh '''
                    chmod +x mvnw
                    ./mvnw clean package -Dmaven.test.skip=true
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t $DOCKER_IMAGE .'
            }
        }

        stage('Run Container') {
            steps {
                sh '''
                    docker stop $CONTAINER_NAME || true
                    docker rm $CONTAINER_NAME || true
                    docker run -d --name $CONTAINER_NAME -p 8040:8080 $DOCKER_IMAGE
                '''
            }
        }
    }
}
