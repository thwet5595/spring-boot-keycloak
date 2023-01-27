package com.mozen.springbootkeycloack;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

//	@Bean
//	public ApplicationRunner run(PlantRepository plantRepository) throws Exception {
//		return (ApplicationArguments args) -> {
//			List<Plant> plants = Arrays.asList(
//					new Plant("subalpine fir", "abies lasiocarpa", "pinaceae"),
//					new Plant("sour cherry", "prunus cerasus", "rosaceae"),
//					new Plant("asian pear", "pyrus pyrifolia", "rosaceae")
//			);
//			plantRepository.saveAll(plants);
//		};
//	}
}
