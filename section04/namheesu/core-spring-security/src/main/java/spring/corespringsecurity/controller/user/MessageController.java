package spring.corespringsecurity.controller.user;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessageController {

    @GetMapping("/messages")
    public String messages() throws Exception{
        return "user/messages";
    }

    @GetMapping("/api/messages")
    public String apiMessage(){
        return "messages ok";
    }
}
