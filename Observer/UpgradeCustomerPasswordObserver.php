<?php
namespace nBits\UpgradeHash\Observer;
use Magento\Framework\Event\ObserverInterface;
use Magento\Customer\Model\ResourceModel\CustomerRepository;
use Magento\Customer\Model\CustomerRegistry;
use Magento\Framework\Encryption\EncryptorInterface;
class UpgradeCustomerPasswordObserver implements ObserverInterface
{
  /**
   * Encryption model
   *
   * @var EncryptorInterface
   */
  protected $encryptor;
  /**
   * @var CustomerRegistry
   */
  protected $customerRegistry;
  /**
   * @var CustomerRepository
   */
  protected $customerRepository;
  public function __construct(
      \Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig,
      EncryptorInterface $encryptor,
      CustomerRegistry $customerRegistry,
      CustomerRepository $customerRepository
  ) {
      $this->scopeConfig = $scopeConfig;
      $this->encryptor = $encryptor;
      $this->customerRegistry = $customerRegistry;
      $this->customerRepository = $customerRepository;
  }
  /*
  Check Prestashop password hash
  */
  private function checkHash($salt, $hash, $pw) {
      $md5 = md5($salt.$pw);
      return ($md5 == $hash);
  }

  /**
   * Upgrade customer password hash when customer has logged in
   *
   * @param \Magento\Framework\Event\Observer $observer
   * @return void
   */
  public function execute(\Magento\Framework\Event\Observer $observer)
  {
      $storeScope = \Magento\Store\Model\ScopeInterface::SCOPE_STORE;
      $enabled = $this->scopeConfig->getValue('nbits_upgradehash/general/enable', $storeScope);
      $salt = $this->scopeConfig->getValue('nbits_upgradehash/general/md5_salt', $storeScope);

      $requestParams = $observer->getEvent()->getData('request')->getParams();
      $username = $requestParams['login']['username'];
      $password = $requestParams['login']['password'];
      try {
          /** @var \Magento\Customer\Api\Data\CustomerInterface */
          $customer = $this->customerRepository->get($username);
          $customerSecure = $this->customerRegistry->retrieveSecureData($customer->getId());
          $hash = $customerSecure->getPasswordHash();
          if ($enabled && $this->checkHash($salt,$hash,$password)) {
              $customerSecure->setPasswordHash($this->encryptor->getHash($password, true));
              $this->customerRepository->save($customer);
          }
      } catch (\Exception $e) {
      }
  }
}
