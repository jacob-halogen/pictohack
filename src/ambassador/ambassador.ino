void myTask(void *pvParameters) {
  for (;;) {
    Serial.println("Hello from my task!");
    vTaskDelay(1000 / portTICK_PERIOD_MS);  // FreeRTOS delay, not delay()
  }
}

void setup() {
  Serial.begin(9600);
  while (!Serial) { delay(10); }

  xTaskCreate(
    myTask,        // function to run
    "MyTask",      // name (for debugging)
    2048,          // stack size in words, not bytes
    NULL,          // parameters to pass in
    1,             // priority (higher number = higher priority)
    NULL           // task handle (optional, NULL if you don't need to reference it later)
  );

  Serial.println("Setup done, task launched");
}

void loop() {
  Serial.println("Hello from loop()");
  delay(1000);
}