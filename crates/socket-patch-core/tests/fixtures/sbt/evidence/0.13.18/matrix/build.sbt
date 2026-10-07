scalaVersion in ThisBuild := "2.10.7"
lazy val root = (project in file(".")).aggregate(a, d, e)
lazy val a = project.settings(libraryDependencies += "org.apache.commons" % "commons-text" % "1.9")
lazy val d = project.settings(crossPaths := false, autoScalaLibrary := false, libraryDependencies += "com.google.code.gson" % "gson" % "2.8.9")
lazy val e = project.settings(crossScalaVersions := Seq("2.10.7", "2.11.12"), libraryDependencies ++= Seq("org.apache.commons" % "commons-lang3" % "3.11", "org.apache.commons" % "commons-lang3" % "3.11" classifier "tests"))
