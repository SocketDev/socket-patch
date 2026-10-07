scalaVersion in ThisBuild := "2.10.7"
lazy val root = (project in file(".")).aggregate(e)
lazy val e = project.settings(crossScalaVersions := Seq("2.10.7", "2.11.12"), libraryDependencies += "org.apache.commons" % "commons-lang3" % "3.11")
