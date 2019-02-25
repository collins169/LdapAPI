package com.kedstudio.ldap.controller;

import com.kedstudio.ldap.utils.ActiveDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

/**
 * Created by logic on 13/09/2017.
 */

@RestController
@RequestMapping("/api")
public class ActiveDirectoryController {

    private Logger log = LoggerFactory.getLogger(ActiveDirectoryController.class);

    @Value("${app.domain}")
    private String ldapDomain;

    @PostMapping("/authenticate")
    public GeneralResponse authenticate(@RequestParam String username, @RequestParam String password){
        GeneralResponse response = new GeneralResponse();

        if(!ActiveDirectory.authenticate(username, password, ldapDomain)){
            response.setRespCode(1);
            response.setRespMsg("Invaild Credentials");
        }else{
            response.setRespCode(0);
            response.setRespMsg("Success");
        }

        log.info("response: {}", response);

        return response;
    }

    public class GeneralResponse {
        private int respCode;
        private String respMsg;

        public int getRespCode() {
            return respCode;
        }

        public void setRespCode(int respCode) {
            this.respCode = respCode;
        }

        public String getRespMsg() {
            return respMsg;
        }

        public void setRespMsg(String respMsg) {
            this.respMsg = respMsg;
        }

        @Override
        public String toString() {
            return "GeneralResponse{" +
                    "respCode=" + respCode +
                    ", respMsg='" + respMsg + '\'' +
                    '}';
        }
    }

}
