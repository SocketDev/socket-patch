lazy val text19 = "org.apache.commons" % "commons-text" % "1.9"
lazy val text110 = "org.apache.commons" % "commons-text" % "1.10.0"
lazy val root = (project in file(".")).aggregate(a, b, c).settings(libraryDependencies += text19)
lazy val a = project.settings(libraryDependencies ++= Seq(text19, "junit" % "junit" % "4.13.2" % Test))
lazy val b = project.settings(libraryDependencies ++= Seq(text110, "com.google.code.gson" % "gson" % "2.8.9"))
lazy val c = project.settings(libraryDependencies ++= Seq(text19, "org.apache.commons" % "commons-lang3" % "3.12.0"))
