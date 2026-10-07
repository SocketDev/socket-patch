ThisBuild / scalaVersion := "2.12.18"

lazy val root = (project in file("."))
  .settings(
    libraryDependencies ++= Seq(
      "org.apache.commons" % "commons-text" % "1.9"
    )
  )
