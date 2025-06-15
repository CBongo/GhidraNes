package ghidranes.util;
import java.lang.annotation.*;

@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface AutoRegister {}
/**
 * This annotation is used to mark mapper classes that should be automatically registered
 * in GhidraNes. Classes annotated with this will be discovered and registered at build time.
 */
