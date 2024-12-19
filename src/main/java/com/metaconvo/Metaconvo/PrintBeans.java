package com.metaconvo.Metaconvo;


import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

//@Component
public class PrintBeans {

    @Autowired
    private ApplicationContext applicationContext;

    @PostConstruct
    public void printAllBeans() {
        String[] allBeanNames = applicationContext.getBeanDefinitionNames();
        System.out.println("Beans in the application context:");
        for (String beanName : allBeanNames) {
            System.out.println(beanName);
        }
    }
}
