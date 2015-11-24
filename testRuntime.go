package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
)

const ConfigJson = "config.json"
const RuntimeJson = "runtime.json"
const RootFS = "rootfs"
const DefaultRuntimeCMD = "runc"
const TestRoot = "./testroot"

const keepFile = true

func validate(caseDir string, rootfsTarURL string, runtimeCMD string, runtimeHelperURL string) error {
	if len(runtimeCMD) == 0 {
		runtimeCMD = DefaultRuntimeCMD
	}
	if _, err := exec.LookPath(runtimeCMD); err != nil {
		return err
	}

	bundleDir, err := prepareBundle(caseDir, rootfsTarURL, runtimeHelperURL)
	if err != nil {
		return err
	}

	cmd := exec.Command(runtimeCMD, "start")
	cmd.Dir = bundleDir
	cmd.Stdin = os.Stdin
	out, err := cmd.CombinedOutput()

	fmt.Println(string(out))

	return err
}

func prepareBundle(caseDir string, rootfsTarURL string, runtimeHelperURL string) (string, error) {
	// Create bundle follder
	testRoot := path.Join(TestRoot, path.Base(caseDir))
	if err := os.RemoveAll(testRoot); err != nil {
		return "", err
	}

	if err := os.MkdirAll(path.Join(testRoot, RootFS), os.ModePerm); err != nil {
		return "", err
	}

	// Untar the rootfs.tar.gz
	if err := UntarFile(rootfsTarURL, path.Join(testRoot, RootFS)); err != nil {
		return "", err
	}

	// Copy the config.json and runtime.json
	dConfigJson := path.Join(testRoot, ConfigJson)
	sConfigJson := path.Join(caseDir, ConfigJson)
	if err := copy(dConfigJson, sConfigJson); err != nil {
		return "", err
	}

	dRuntimeJson := path.Join(testRoot, RuntimeJson)
	sRuntimeJson := path.Join(caseDir, RuntimeJson)
	if err := copy(dRuntimeJson, sRuntimeJson); err != nil {
		return "", err
	}
	// Copy runtimHelper from runtimeHelperURL to rootfs/runtimeHelper
	dRuntimeTest := path.Join(testRoot, RootFS, path.Base(runtimeHelperURL))
	if err := copy(dRuntimeTest, runtimeHelperURL); err != nil {
		fmt.Println(err)
		return "", err
	}
	if err := os.Chmod(dRuntimeTest, os.ModePerm); err != nil {
		return "", err
	}

	// Copy config.json and runtime.json to rootfs/
	dTestConfigJson := path.Join(testRoot, ConfigJson)
	if err := copy(dTestConfigJson, sConfigJson); err != nil {
		return "", err
	}

	dTestRuntimeJson := path.Join(testRoot, RuntimeJson)
	if err := copy(dTestRuntimeJson, sRuntimeJson); err != nil {
		return "", err
	}
	return testRoot, nil
}

func copy(dst string, src string) error {
	fmt.Println("Copy ", dst, src)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

func UntarFile(filename string, dDir string) error {
	if _, err := os.Stat(filename); err != nil {
		return err
	}

	fr, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fr.Close()
	gr, err := gzip.NewReader(fr)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		dURL := path.Join(dDir, h.Name)
		tmpDir := path.Dir(dURL)
		if p, err := os.Stat(tmpDir); err != nil {
			if !os.IsExist(err) {
				os.MkdirAll(tmpDir, os.ModePerm)
			}
		} else {
			if !p.IsDir() {
				os.Remove(tmpDir)
				os.MkdirAll(tmpDir, os.ModePerm)
			}
		}

		fw, err := os.OpenFile(dURL, os.O_CREATE|os.O_WRONLY, os.FileMode(h.Mode))
		if err != nil {
			//Dir for example
			continue
		} else {
			io.Copy(fw, tr)
			fw.Close()
		}
	}
	return nil
}

func main() {
	validate("testcase", "./rootfs.tar.gz", "", "./runtimetest")
}
