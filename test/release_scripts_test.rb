# frozen_string_literal: true

require "minitest/autorun"
require "fileutils"
require "json"
require "open3"
require "tmpdir"

class ReleaseVersionTest < Minitest::Test
  SCRIPT = File.expand_path("../scripts/release-version", __dir__)

  def setup
    @root = Dir.mktmpdir("release-version")
    File.write(File.join(@root, "Cargo.toml"), <<~TOML)
      [package]
      name = "hostcensus"
      version = "1.2.3"

      [dependencies]
      sha2 = { version = "0.11" }

      [workspace.package]
      version = "9.9.9"
    TOML
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def test_prints_the_package_version
    output, status = run_script

    assert status.success?, output
    assert_equal "1.2.3\n", output
  end

  def test_accepts_the_tag_of_that_version
    output, status = run_script("v1.2.3")

    assert status.success?, output
    assert_equal "1.2.3\n", output
  end

  def test_refuses_any_other_tag
    %w[v1.2.4 1.2.3 v1.2.3-rc1 v1.2].each do |tag|
      output, status = run_script(tag)

      refute status.success?, "#{tag} was accepted"
      assert_includes output, "tag #{tag} is not a release of this tree"
    end
  end

  def test_fails_without_a_package_version
    File.write(File.join(@root, "Cargo.toml"), "[dependencies]\nsha2 = { version = \"0.11\" }\n")

    output, status = run_script

    refute status.success?
    assert_includes output, "no [package] version"
  end

  private
    def run_script(*arguments)
      Open3.capture2e(SCRIPT, *arguments, chdir: @root)
    end
end

class CheckReleaseBundleTest < Minitest::Test
  SCRIPT = File.expand_path("../scripts/check-release-bundle", __dir__)
  COMMIT = "0123456789abcdef0123456789abcdef01234567"

  def setup
    @root = Dir.mktmpdir("check-release-bundle")
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def test_passes_a_bundle_from_the_named_build
    output, status = check(bundle)

    assert status.success?, output
    assert_includes output, %("version":"1.2.3")
  end

  def test_fails_a_bundle_from_another_version
    output, status = check(bundle(version: "1.2.2"))

    refute status.success?
    assert_includes output, "written by hostcensus 1.2.3"
  end

  def test_fails_a_bundle_from_another_commit
    _output, status = check(bundle(commit: "f" * 40))

    refute status.success?
  end

  def test_fails_a_bundle_without_a_commit
    _output, status = check(bundle(commit: nil))

    refute status.success?
  end

  def test_fails_another_format
    _output, status = check(bundle(format: "hostcensus.bundle/2"))

    refute status.success?
  end

  def test_fails_a_file_that_is_not_json
    _output, status = check("Census written to standard output\n")

    refute status.success?
  end

  private
    def bundle(format: "hostcensus.bundle/1", version: "1.2.3", commit: COMMIT)
      tool = { name: "hostcensus", version: version, commit: commit }.compact
      JSON.generate(format: format, tool: tool, host: { os: "linux" }, scan: { privileged: true, scanners: {} })
    end

    def check(content)
      path = File.join(@root, "census.json")
      File.write(path, content)
      Open3.capture2e(SCRIPT, path, "1.2.3", COMMIT)
    end
end
