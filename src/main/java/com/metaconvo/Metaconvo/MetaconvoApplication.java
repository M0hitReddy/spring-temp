package com.metaconvo.Metaconvo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MetaconvoApplication implements CommandLineRunner {

	@Autowired
    private PrintBeans printBeans;

	public static void main(String[] args) {

		SpringApplication.run(MetaconvoApplication.class, args);
//		printBeans.printAllBeans();
	}

	@Override
	public void run(String... args) throws Exception {
		printBeans.printAllBeans();
	}

}
