package com.example.vaccination.config;

import com.example.vaccination.handler.RedirectInterceptorHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Autowired
    RedirectInterceptorHandler redirectInterceptorHandler;
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Áp dụng cho tất cả các URL /register
        registry.addInterceptor(redirectInterceptorHandler).addPathPatterns("/");
    }
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        exposeDirectory("vaccine-type-images", registry);
    }

    private void exposeDirectory(String dirName, ResourceHandlerRegistry registry) {
        Path uploadDir = Paths.get(dirName);
        String uploadPath = uploadDir.toFile().getAbsolutePath();

        if (dirName.startsWith("../")) dirName = dirName.replace("../", "");

        registry.addResourceHandler("/" + dirName + "/**").addResourceLocations("file:/"+ uploadPath + "/");
    }

}
