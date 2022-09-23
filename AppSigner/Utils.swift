//
//  Utils.swift
//  AppSigner
//
//  Created by mumu on 2022/9/22.
//

import Foundation

// MARK: - 常量
let signableExtensions = ["dylib","so","0","vis","pvr","framework","appex","app"]
let fileManager = FileManager.default
let bundleID = "com.mumu.appsigner"
let mktempPath = "/usr/bin/mktemp"
let unzipPath = "/usr/bin/unzip"
let zipPath = "/usr/bin/zip"
let defaultsPath = "/usr/bin/defaults"
let codesignPath = "/usr/bin/codesign"
let securityPath = "/usr/bin/security"
let chmodPath = "/bin/chmod"
let findPath = "/usr/bin/find"

/// 创建临时文件夹
func makeTempFolder() -> String? {
   let tempTask = Process().execute(mktempPath, workingDirectory: nil, arguments: ["-d","-t", bundleID])
   if tempTask.status != 0 {
       return nil
   }
   return tempTask.output.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
}

// MARK: 解压
func unzip(_ inputFile: String, outputPath: String)->AppSignerTaskOutput {
   return Process().execute(unzipPath, workingDirectory: nil, arguments: ["-q",inputFile,"-d",outputPath])
}

// MARK: 压缩
func zip(_ inputPath: String, outputFile: String)->AppSignerTaskOutput {
   return Process().execute(zipPath, workingDirectory: inputPath, arguments: ["-qry", outputFile, "."])
}

// MARK: 签名
@discardableResult
func codeSign(_ file: String, certificate: String, entitlements: String?,before:((_ file: String, _ certificate: String, _ entitlements: String?)->Void)?, after: ((_ file: String, _ certificate: String, _ entitlements: String?, _ codesignTask: AppSignerTaskOutput)->Void)?)->AppSignerTaskOutput{

   var needEntitlements: Bool = false
   let filePath: String
   switch file.pathExtension.lowercased() {
   case "framework":
       // append executable file in framework
       let fileName = file.lastPathComponent.stringByDeletingPathExtension
       filePath = file.stringByAppendingPathComponent(fileName)
   case "app", "appex":
       // read executable file from Info.plist
       let infoPlist = file.stringByAppendingPathComponent("Info.plist")
       let executableFile = getPlistKey(infoPlist, keyName: "CFBundleExecutable")!
       filePath = file.stringByAppendingPathComponent(executableFile)

       if let entitlementsPath = entitlements, fileManager.fileExists(atPath: entitlementsPath) {
           needEntitlements = true
       }
   default:
       filePath = file
   }

   if let beforeFunc = before {
       beforeFunc(file, certificate, entitlements)
   }

   var arguments = ["-f", "-s", certificate, "--generate-entitlement-der"]
   if needEntitlements {
       arguments += ["--entitlements", entitlements!]
   }
   arguments.append(filePath)

   let codesignTask = Process().execute(codesignPath, workingDirectory: nil, arguments: arguments)
   if codesignTask.status != 0 {
       fatalError("Error codesign: \(codesignTask.output)")
   }

   if let afterFunc = after {
       afterFunc(file, certificate, entitlements, codesignTask)
   }
   return codesignTask
}

/// 递归遍历文件夹
func recursiveDirectorySearch(_ path: String, extensions: [String], found: ((_ file: String) -> Void)){

   if let files = try? fileManager.contentsOfDirectory(atPath: path) {
       var isDirectory: ObjCBool = true

       for file in files {
           let currentFile = path.stringByAppendingPathComponent(file)
           fileManager.fileExists(atPath: currentFile, isDirectory: &isDirectory)
           if isDirectory.boolValue {
               recursiveDirectorySearch(currentFile, extensions: extensions, found: found)
           }
           if extensions.contains(file.pathExtension) {
               if file.pathExtension != "" || file == "IpaSecurityRestriction" {
                   found(currentFile)
               } else {
                   //NSLog("couldnt find: %@", file)
               }
           } else if isDirectory.boolValue == false && checkMachOFile(currentFile) {
               found(currentFile)
           }

       }
   }
}

// 检查是否是 MachO 我那件
func checkMachOFile(_ path: String) -> Bool {
   if let file = FileHandle(forReadingAtPath: path) {
       let data = file.readData(ofLength: 4)
       file.closeFile()
       var machOFile = data.elementsEqual([0xCE, 0xFA, 0xED, 0xFE]) || data.elementsEqual([0xCF, 0xFA, 0xED, 0xFE]) || data.elementsEqual([0xCA, 0xFE, 0xBA, 0xBE])

       if machOFile == false && signableExtensions.contains(path.lastPathComponent.pathExtension.lowercased()) {
           print("Detected binary by extension: \(path)")
           machOFile = true
       }
       return machOFile
   }
   return false
}

// MARK: 清理文件夹
func cleanup(_ tempFolder: String){
   do {
       try fileManager.removeItem(atPath: tempFolder)
   } catch let error as NSError {
       fatalError("Unable to delete temp folder: \(error)")
   }
}

// MARK: 解析 Plist Key
func getPlistKey(_ plist: String, keyName: String)->String? {
   let dictionary = NSDictionary(contentsOfFile: plist);
   return dictionary?[keyName] as? String
}
