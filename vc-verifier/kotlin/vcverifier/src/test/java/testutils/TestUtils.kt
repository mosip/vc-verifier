package testutils

import org.springframework.util.ResourceUtils
import java.nio.file.Files

fun readClasspathFile(path: String): String =
    String(Files.readAllBytes(ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + path).toPath()))

