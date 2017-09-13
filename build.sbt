
name := "web-push"

organization := "com.zivver"

version := "0.1.2"

scalaVersion := "2.12.1"

crossScalaVersions := Seq("2.11.8", "2.12.1")

resolvers += "Typesafe Repository" at "http://repo.typesafe.com/typesafe/releases/"

val akkaVersion = "10.0.9"

libraryDependencies ++= Seq(
  "com.pauldijou" %% "jwt-core" % "0.10.0",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.55",
  "com.typesafe.akka" %% "akka-http" % akkaVersion
)

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases" at nexus + "service/local/staging/deploy/maven2")
}

publishMavenStyle := true

publishArtifact in Test := false

pomIncludeRepository := { _ => false }

pomExtra := (
  <url>http://your.project.url</url>
    <licenses>
      <license>
        <name>MIT License</name>
        <url>http://www.opensource.org/licenses/mit-license.php</url>
        <distribution>repo</distribution>
      </license>
    </licenses>
    <scm>
      <url>git@github.com:zivver/web-push.git</url>
      <connection>scm:git:git@github.com:zivver/web-push.git</connection>
    </scm>
    <developers>
      <developer>
        <id>zivver</id>
        <name>Zivver</name>
        <url>https://www.zivver.com</url>
      </developer>
    </developers>
  )
