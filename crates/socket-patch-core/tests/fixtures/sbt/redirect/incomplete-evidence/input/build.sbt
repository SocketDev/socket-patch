ThisBuild / scalaVersion := "2.12.18"

lazy val root = (project in file("."))
  .settings(
    libraryDependencies ++= Seq(
      "org.apache.commons" % "commons-lang3" % "3.11"
    )
  )
lazy val core = project.in(file("core"))
