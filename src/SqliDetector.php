<?php
    namespace mai20\SqliDetector;

    class SqliDetector {
        private $url = '';
        private $text = '';
        private $sql_error;
        private $payload;
        private $start;
        private $end;
        private $res;
        private $conn;
        private $htmlObject;
        private $vulnerability = array();

        function __construct() {
        }

        public function setPayload($filepayload){
            $this->payload = explode("\n", file_get_contents($filepayload));
        }

        public function setSqlError($file){
            $this->sql_error = explode("\n", file_get_contents($file));
        }

        public function setUrl($url){
            $this->url = $url;
        }

        private function checkVuln($res, $url, $method, $payload){
            foreach($this->sql_error as $error) {
                $e = strtolower($error);
                if(preg_match("/$e/", strtolower($res))) {
                    array_push($this->vulnerability, array("link" => $url, "type" => "inband", "method" => $method, "error" => $e, "payload" => $payload));
                }
            }
        }

        private function executeGet($u, $param, $blind = FALSE){
            if($blind == TRUE){
                $this->start = time();
                $this->conn = curl_init($u . $param);
                curl_setopt($this->conn, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($this->conn, CURLOPT_SSL_VERIFYPEER,false);
                curl_setopt($this->conn, CURLOPT_TIMEOUT, 200);
                curl_setopt($this->conn, CURLOPT_HEADER, 1);
                curl_setopt($this->conn, CURLOPT_FOLLOWLOCATION, 1);
                curl_setopt($this->conn, CURLOPT_REFERER, "http://google.com");
                curl_setopt($this->conn, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9');
                $this->res = curl_exec($this->conn);
                $this->end = time();
                if($this->end - $this->start > 9){
                    array_push($this->vulnerability, array("link" => $u, "type" => "blind", "method" => "GET", "payload" => $param));
                }
            }else{
                $this->conn = curl_init($u . $param);
                curl_setopt($this->conn, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($this->conn, CURLOPT_SSL_VERIFYPEER,false);
                curl_setopt($this->conn, CURLOPT_TIMEOUT, 200);
                curl_setopt($this->conn, CURLOPT_HEADER, 1);
                curl_setopt($this->conn, CURLOPT_FOLLOWLOCATION, 1);
                curl_setopt($this->conn, CURLOPT_REFERER, "http://google.com");
                curl_setopt($this->conn, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9');
                $this->res = curl_exec($this->conn);
                $this->checkVuln($this->res, $u, "GET", $param);
            }
            curl_close($this->conn);
        }

        private function executePost($u, $field, $blind = FALSE){
            if($blind == TRUE){
                $this->start = time();
                $this->conn = curl_init($u);
                curl_setopt($this->conn, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($this->conn, CURLOPT_SSL_VERIFYPEER,false);
                curl_setopt($this->conn, CURLOPT_TIMEOUT, 200);
                curl_setopt($this->conn, CURLOPT_HEADER, 1);
                curl_setopt($this->conn, CURLOPT_FOLLOWLOCATION, 1);
                curl_setopt($this->conn, CURLOPT_REFERER, "http://google.com");
                curl_setopt($this->conn, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9');
                curl_setopt($this->conn, CURLOPT_POST, 1);
                curl_setopt($this->conn, CURLOPT_POSTFIELDS, $field);
                $this->res = curl_exec($this->conn);
                $this->end = time();
                if($this->end - $this->start > 9){
                    array_push($this->vulnerability, array("link" => $u, "type" => "blind", "method" => "POST", "payload" => $field));
                }
            }else{
                $this->conn = curl_init($u);
                curl_setopt($this->conn, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($this->conn, CURLOPT_SSL_VERIFYPEER,false);
                curl_setopt($this->conn, CURLOPT_TIMEOUT, 200);
                curl_setopt($this->conn, CURLOPT_HEADER, 1);
                curl_setopt($this->conn, CURLOPT_FOLLOWLOCATION, 1);
                curl_setopt($this->conn, CURLOPT_REFERER, "http://google.com");
                curl_setopt($this->conn, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9');
                curl_setopt($this->conn, CURLOPT_POST, 1);
                curl_setopt($this->conn, CURLOPT_POSTFIELDS, $field);
                $this->res = curl_exec($this->conn);
                $this->checkVuln($this->res, $u, "POST", $field);
            }
            curl_close($this->conn);            
        }

        public function execute(){
            foreach($this->payload as $p){
                $this->executePost($this->url, $p, FALSE);
                $this->executePost($this->url, $p, TRUE);
                $this->executeGet($this->url, $p, FALSE);
                $this->executeGet($this->url, $p, TRUE);
            }

            if(sizeof($this->vulnerability) > 0){
                array_push($this->vulnerability, array('Result' => "You\'re Bad" ));
            }else{
                array_push($this->vulnerability, array('Result' => "You\'re Good" ));
            }

            return $this->vulnerability;
        }
    }