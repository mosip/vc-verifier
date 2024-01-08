package io.mosip.tools.vc;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import io.mosip.tools.vc.verifier.VCVerifier;

@SpringBootApplication
public class VcVerifierApplication {

	public static void main(String[] args) {
		if(args.length != 1) {
			System.out.println("Invalid arguments. Specify a credential file to verify.");
			return;
		}
		ConfigurableApplicationContext context = SpringApplication.run(VcVerifierApplication.class, args);
		VCVerifier vcVerifier = context.getBean(VCVerifier.class);
		context.close();
		try {
			boolean verify = vcVerifier.verify(Files.readString(Path.of(new File(args[0]).toURI())));
			if(verify) {
				System.out.println("{\"verificationStatus\":\"success\"}");
			} else {
				System.err.println("{\"verificationStatus\":\"failed\"}");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
