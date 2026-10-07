ThisBuild / scalaVersion := "3.8.4"
lazy val root = (project in file(".")).aggregate(xb)
lazy val xb = Project("x-build", file("xb")).settings(libraryDependencies += "com.google.code.gson" % "gson" % "2.8.9")
