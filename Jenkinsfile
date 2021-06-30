pipeline {

    environment {
        DOCKER_HOST='docker.hem:2376'
    }

    agent any;

    stages {
        stage('Build') {
            agent {
                dockerfile { dir 'build-deps' }
            }

            steps {
                dir('build') {
                    sh 'cmake ..'
                    sh 'make -j4'
                }
            }
        }
    }

    triggers {
        pollSCM('H */4 * * 1-5')
    }
}

