ThisBuild / scalaVersion := "2.12.18"
ThisBuild / useCoursier := false
lazy val root = (project in file(".")).aggregate(a)
lazy val a = project.settings(libraryDependencies ++= Seq("org.apache.commons" % "commons-text" % "1.9", "org.apache.commons" % "commons-lang3" % "3.12.0"))
