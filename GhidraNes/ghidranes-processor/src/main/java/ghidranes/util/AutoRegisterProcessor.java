package ghidranes.util;

import javax.annotation.processing.*;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.*;
import javax.tools.JavaFileObject;
import java.io.Writer;
import java.util.Set;
import java.util.stream.Collectors;

@SupportedAnnotationTypes("ghidranes.util.AutoRegister")
@SupportedSourceVersion(SourceVersion.RELEASE_9)
public class AutoRegisterProcessor extends AbstractProcessor {
    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        Set<? extends Element> elements = roundEnv.getElementsAnnotatedWith(AutoRegister.class);
        if (elements.isEmpty()) return false;
        try {
            String pkg = "ghidranes.util";
            String className = "NesMapperRegistry";
            JavaFileObject file = processingEnv.getFiler().createSourceFile(pkg + "." + className);
            try (Writer writer = file.openWriter()) {
                writer.write("package " + pkg + ";\n\n");
                writer.write("import java.util.Arrays;\nimport java.util.List;\n");
                writer.write("import ghidranes.mappers.NesMapper;\n");
                for (Element e : elements) {
                    writer.write("import " + ((TypeElement)e).getQualifiedName() + ";\n");
                }
                writer.write("\npublic class " + className + " {\n");
                writer.write("    public static List<Class<? extends NesMapper>> getAll() {\n");
                writer.write("        return Arrays.asList(\n");
                writer.write(
                    elements.stream()
                        .map(e -> ((TypeElement)e).getQualifiedName() + ".class")
                        .collect(Collectors.joining(",\n            "))
                );
                writer.write("\n        );\n    }\n}\n");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }
}