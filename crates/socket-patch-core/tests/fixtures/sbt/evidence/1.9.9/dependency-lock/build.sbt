ThisBuild / scalaVersion := "2.12.18"
lazy val root = (project in file(".")).aggregate(a)
lazy val a = project.settings(libraryDependencies += "org.apache.commons" % "commons-text" % "1.9")
