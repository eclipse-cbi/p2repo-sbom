def boolean useCredentials = false

pipeline {
  agent { label 'ubuntu-latest' }

   options {
    timestamps()
    timeout(time: 30, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '10'))
    disableConcurrentBuilds()
    checkoutToSubdirectory('p2repo-sbom')
  }

  tools {
    maven 'apache-maven-latest'
    jdk 'temurin-jdk25-latest'
  }

  environment {
    CHECKOUT = 'false'
    PUBLISH_LOCATION = 'cbi/updates/p2-sbom'
    GITHUB_REPO = 'eclipse-cbi/p2repo-sbom'
  }

  parameters {
    choice(
      name: 'BUILD_TYPE',
      choices: ['nightly', 'milestone', 'release'],
      description: '''
        Choose the type of build.
        Note that a release build will not promote the build, but rather will promote the most recent milestone build.
        '''
    )

    booleanParam(
      name: 'PROMOTE',
      defaultValue: true,
      description: 'Whether to promote the build to the download server.'
    )

    booleanParam(
      name: 'ARCHIVE',
      defaultValue: false,
      description: 'Whether to archive the workspace.'
    )
  }

  stages {
    stage('Display Parameters') {
      steps {
        script {
          def description = """
BUILD_TYPE=${params.BUILD_TYPE}
BRANCH_NAME=${env.BRANCH_NAME}
PROMOTE=${params.PROMOTE}
ARCHIVE=${params.ARCHIVE}
""".trim()
          echo description
          currentBuild.description = description.replace("\n", "<br/>")
          env.BUILD_TYPE = params.BUILD_TYPE
          if (env.BRANCH_NAME == 'main' || env.BRANCH_NAME == null) {
            useCredentials = true
            if (params.PROMOTE) {
              env.SIGN = true
              env.PROMOTE = true
            } else {
              env.SIGN = false
              env.NOTARIZE = false
              env.PROMOTE = false
            }
          } else {
            useCredentials = false
            env.SIGN = false
            env.NOTARIZE = false
            env.PROMOTE = false
          }
        }
      }
    }

    stage('Build Tools and Products') {
      steps {
        script {
           dir('p2repo-sbom/releng/org.eclipse.cbi.p2repo.sbom.releng.parent') {
            if (useCredentials) {
              sshagent(['projects-storage.eclipse.org-bot-ssh']) {
                mvn()
              }
            } else {
              mvn()
            }
          }
        }
      }
    }

    stage('Archive Results') {
      when {
        expression {
          params.ARCHIVE
        }
      }
      steps {
        archiveArtifacts 'p2repo-sbom/**'
      }
    }
  }

  post {
    failure {
      mail to: 'ed.merks@gmail.com',
      subject: "[CBI p2 SBOM] Build Failure ${currentBuild.fullDisplayName}",
      mimeType: 'text/html',
      body: "Project: ${env.JOB_NAME}<br/>Build Number: ${env.BUILD_NUMBER}<br/>Build URL: ${env.BUILD_URL}<br/>Console: ${env.BUILD_URL}/console"
    }

    fixed {
      mail to: 'ed.merks@gmail.com',
      subject: "[CBI p2 SBOM] Back to normal ${currentBuild.fullDisplayName}",
      mimeType: 'text/html',
      body: "Project: ${env.JOB_NAME}<br/>Build Number: ${env.BUILD_NUMBER}<br/>Build URL: ${env.BUILD_URL}<br/>Console: ${env.BUILD_URL}/console"
    }

    cleanup {
      deleteDir()
    }
  }
}

def void mvn() {
  sh '''
    pwd
    if [[ $PROMOTE == false ]]; then
      promotion_argument='-Dorg.eclipse.justj.p2.manager.args='
      sign_argument=''
    else
      sign_argument='-Peclipse-sign -Ppromote'
    fi
    mvn \
      --no-transfer-progress\
      $promotion_argument \
      -Dorg.eclipse.storage.user=genie.cbi \
      -Dorg.eclipse.justj.p2.manager.build.url=$JOB_URL \
      -Dorg.eclipse.download.location.relative=$PUBLISH_LOCATION \
      -Dorg.eclipse.justj.p2.manager.relative= \
      -Dbuild.type=$BUILD_TYPE \
      -Dgit.commit=$GIT_COMMIT \
      -Dbuild.id=$BUILD_NUMBER \
      -DskipTests=false \
      $sign_argument \
      clean \
      verify
    '''
}